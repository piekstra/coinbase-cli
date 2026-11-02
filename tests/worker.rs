//! The Worker module (feature `wasm`), natively: each call goes through the
//! same ABI functions the WebAssembly exports call, with the test playing the
//! Worker (`pk_cli_mcp::wasm::testing`). Every JWT the module sends is
//! verified against the dummy key's public half, and Coinbase answers from
//! the scrubbed fixtures.
#![cfg(feature = "wasm")]

use std::collections::HashSet;

use base64::Engine as _;
use cbase::worker::tools;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::DecodePrivateKey as _;
use pk_cli_core::transport::{HttpRequest, HttpResponse};
use pk_cli_mcp::wasm::testing::{call, describe, take_logs, Asked, Reply};
use pk_cli_mcp::wasm::Level;
use serde_json::{json, Value};

const KEY_NAME: &str = "organizations/00000000-0000-0000-0000-000000000000/apiKeys/11111111-1111-1111-1111-111111111111";

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn ok(body: String) -> Reply {
    Reply::Response(HttpResponse::new(200, body))
}

/// The accounts listing's two fixture pages, by cursor.
fn accounts_page(req: &HttpRequest) -> Reply {
    if req.url.contains("starting_after=") {
        ok(fixture("accounts_last_page.json"))
    } else {
        ok(fixture("accounts.json"))
    }
}

/// A throwaway P-256 key: its PEM as a settings field would hold it (literal
/// `\n` escapes, the way the key file's JSON shows it), and its public half.
fn dummy_ec_key() -> (String, p256::ecdsa::VerifyingKey) {
    let secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
    let pem = secret
        .to_sec1_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let public = p256::ecdsa::VerifyingKey::from(secret.public_key());
    (pem.trim().replace('\n', "\\n"), public)
}

fn config(private_key: &str) -> Value {
    json!({ "CBASE_API_KEY_NAME": KEY_NAME, "CBASE_API_PRIVATE_KEY": private_key })
}

fn b64(part: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap()
}

/// The CDP JWT on `req`, checked the way Coinbase checks it: ES256 under
/// `public`, `kid` = `sub` = the key name, `uri` the path without its query,
/// valid from now (the Worker's clock) for two minutes, a 128-bit nonce never
/// seen before. Returns the `uri` claim.
fn verify_jwt(
    req: &HttpRequest,
    public: &p256::ecdsa::VerifyingKey,
    nonces: &mut HashSet<String>,
) -> String {
    let token = req
        .header_value("Authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .expect("a bearer token");
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&b64(parts[0])).unwrap();
    let claims: Value = serde_json::from_slice(&b64(parts[1])).unwrap();
    let signature = p256::ecdsa::Signature::from_slice(&b64(parts[2])).unwrap();
    public
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("the JWT verifies under the key's public half");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], KEY_NAME);
    assert_eq!(claims["sub"], KEY_NAME);
    assert_eq!(claims["iss"], "cdp");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nbf = claims["nbf"].as_u64().unwrap();
    assert!(nbf.abs_diff(now) <= 5, "nbf {nbf}, now {now}");
    assert_eq!(claims["exp"].as_u64(), Some(nbf + 120));
    let nonce = header["nonce"].as_str().unwrap();
    assert_eq!(nonce.len(), 32, "{nonce}");
    assert!(nonces.insert(nonce.to_string()));
    assert_eq!(req.header_value("CB-VERSION"), Some("2022-01-06"));
    assert_eq!(
        req.header_value("User-Agent"),
        Some(concat!("cbase/", env!("CARGO_PKG_VERSION")))
    );
    claims["uri"].as_str().unwrap().to_string()
}

#[test]
fn the_tools_are_described_for_a_worker_without_any_key() {
    let d = describe(tools);
    let names: Vec<&str> = d["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["coinbase_accounts", "coinbase_transactions"]);
    let instructions = d["instructions"].as_str().unwrap();
    assert!(instructions.contains("Cloudflare Worker"), "{instructions}");
    assert!(!instructions.contains("auth login"), "{instructions}");
    assert_eq!(d["server"]["name"], "cbase");
    assert_eq!(d["server"]["version"], env!("CARGO_PKG_VERSION"));
}

/// The Worker signs with WebCrypto: the module hands it the key as PKCS#8
/// DER and the signing input, and uses the signature it gets back.
#[test]
fn accounts_walk_both_pages_with_tokens_the_platform_signs() {
    let (pem, public) = dummy_ec_key();
    let mut nonces = HashSet::new();
    let mut uris = Vec::new();
    let mut signed = 0;
    let out = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {"include_zero": true}}),
        config(&pem),
        |asked| match asked {
            Asked::SignEs256 { key, data } => {
                signed += 1;
                let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key).expect("PKCS#8 DER");
                let sig: p256::ecdsa::Signature = key.sign(&data);
                Reply::Signature(sig.to_bytes().to_vec())
            }
            Asked::Fetch(req) => {
                uris.push(verify_jwt(&req, &public, &mut nonces));
                accounts_page(&req)
            }
        },
    );
    let result = &out["result"];
    assert_eq!(result["isError"], false, "{out}");
    let items = result["structuredContent"]["items"].as_array().unwrap();
    assert!(items.len() > 3, "both pages: {items:?}");
    assert_eq!(signed, 2, "one token per page, both signed by the platform");
    assert_eq!(uris, ["GET api.coinbase.com/v2/accounts"; 2]);
}

/// A Worker without WebCrypto ECDSA, one that refuses the key, or one that
/// answers with something other than a 64-byte `r || s` leaves the module to
/// sign in WebAssembly; the token is just as valid. Only a platform that
/// tried and failed is worth a line in the Worker's log.
#[test]
fn the_module_signs_itself_when_the_platform_cannot() {
    for (refusal, warns) in [
        (Reply::Unsupported, false),
        (Reply::Failed("DataError: bad key".into()), true),
        (Reply::Signature(vec![0x30; 70]), true),
    ] {
        take_logs();
        let (pem, public) = dummy_ec_key();
        let mut nonces = HashSet::new();
        let out = call(
            tools,
            json!({"name": "coinbase_transactions", "arguments": {"account": "20000000-0000-0000-0000-000000000001"}}),
            config(&pem),
            |asked| match asked {
                Asked::SignEs256 { .. } => refusal.clone(),
                Asked::Fetch(req) => {
                    let uri = verify_jwt(&req, &public, &mut nonces);
                    if uri.ends_with("/transactions") {
                        ok(fixture("transactions.json"))
                    } else {
                        accounts_page(&req)
                    }
                }
            },
        );
        assert_eq!(out["result"]["isError"], false, "{out}");
        let warnings: Vec<String> = take_logs()
            .into_iter()
            .filter(|(level, _)| *level == Level::Warn)
            .map(|(_, line)| line)
            .collect();
        assert_eq!(!warnings.is_empty(), warns, "{refusal:?}: {warnings:?}");
        assert!(
            warnings.iter().all(|w| w.contains("signing in-process")),
            "{warnings:?}"
        );
    }
}

/// The isolate keeps the last key it parsed: the same key again is served
/// from it, a rotated key is parsed afresh (never the old one's signer), and
/// a key that fails to parse is not kept.
#[test]
fn a_rotated_key_signs_with_the_new_key() {
    let (first, first_public) = dummy_ec_key();
    let (second, second_public) = dummy_ec_key();
    let accounts = |pem: &str, public: &p256::ecdsa::VerifyingKey| {
        let mut nonces = HashSet::new();
        call(
            tools,
            json!({"name": "coinbase_accounts", "arguments": {}}),
            config(pem),
            |asked| match asked {
                Asked::SignEs256 { .. } => Reply::Unsupported,
                Asked::Fetch(req) => {
                    verify_jwt(&req, public, &mut nonces);
                    accounts_page(&req)
                }
            },
        )
    };
    for (pem, public) in [
        (&first, &first_public),
        (&first, &first_public),
        (&second, &second_public),
    ] {
        let out = accounts(pem, public);
        assert_eq!(out["result"]["isError"], false, "{out}");
    }
    let out = accounts("not a key", &second_public);
    assert_eq!(out["result"]["isError"], true, "{out}");
    let out = accounts(&second, &second_public);
    assert_eq!(out["result"]["isError"], false, "{out}");
}

#[test]
fn the_base_url_points_the_module_at_a_mock() {
    let (pem, _) = dummy_ec_key();
    let mut cfg = config(&pem);
    cfg["CBASE_BASE_URL"] = json!("http://127.0.0.1:8788");
    let mut urls = Vec::new();
    call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        cfg,
        |asked| match asked {
            Asked::SignEs256 { .. } => Reply::Unsupported,
            Asked::Fetch(req) => {
                urls.push(req.url.clone());
                ok(fixture("accounts_last_page.json"))
            }
        },
    );
    assert_eq!(urls, ["http://127.0.0.1:8788/v2/accounts?limit=100"]);
}

fn text(out: &Value) -> &str {
    assert_eq!(out["result"]["isError"], true, "{out}");
    out["result"]["content"][0]["text"].as_str().unwrap()
}

#[test]
fn a_missing_or_half_set_key_names_the_worker_secrets_and_fetches_nothing() {
    let never = |asked: Asked| -> Reply { panic!("nothing should be asked: {asked:?}") };
    let none = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        json!({}),
        never,
    );
    let t = text(&none);
    assert!(
        t.starts_with("auth: no Coinbase API key is configured"),
        "{t}"
    );
    assert!(
        t.contains("CBASE_API_KEY_NAME and CBASE_API_PRIVATE_KEY secrets"),
        "{t}"
    );
    assert!(t.contains("Cloudflare Worker's secrets"), "{t}");
    assert!(!t.contains("cbase auth"), "{t}");

    let half = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        json!({"CBASE_API_KEY_NAME": KEY_NAME}),
        never,
    );
    let t = text(&half);
    assert!(
        t.contains("CBASE_API_KEY_NAME is set but CBASE_API_PRIVATE_KEY is not"),
        "{t}"
    );
    assert!(!t.contains("keychain"), "{t}");

    let garbage = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        config("not a key"),
        never,
    );
    assert!(text(&garbage).starts_with("auth: "), "{garbage}");
}

#[test]
fn a_rejected_key_and_a_failed_fetch_say_what_to_do_in_a_worker() {
    let (pem, _) = dummy_ec_key();
    let rejected = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        config(&pem),
        |asked| match asked {
            Asked::SignEs256 { .. } => Reply::Unsupported,
            Asked::Fetch(_) => Reply::Response(HttpResponse::new(401, "Unauthorized")),
        },
    );
    let t = text(&rejected);
    assert!(
        t.starts_with("auth: Coinbase rejected the API key (HTTP 401)"),
        "{t}"
    );
    assert!(t.contains("Cloudflare Worker's secrets"), "{t}");
    assert!(!t.contains("cbase auth"), "{t}");

    let unreachable = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        config(&pem),
        |asked| match asked {
            Asked::SignEs256 { .. } => Reply::Unsupported,
            Asked::Fetch(_) => Reply::Failed("TypeError: fetch failed".into()),
        },
    );
    let t = text(&unreachable);
    assert!(
        t.starts_with("upstream: the request to https://api.coinbase.com failed"),
        "{t}"
    );
    assert!(!t.contains("/v2/accounts"), "the path stays out: {t}");
}

/// A key minted after Coinbase's Ed25519 switch: the module signs EdDSA
/// itself and never asks the platform for ES256.
#[test]
fn an_ed25519_key_is_signed_in_the_module() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let mut pair = key.to_bytes().to_vec();
    pair.extend_from_slice(key.verifying_key().as_bytes());
    let b64key = base64::engine::general_purpose::STANDARD.encode(&pair);
    let out = call(
        tools,
        json!({"name": "coinbase_accounts", "arguments": {}}),
        json!({"CBASE_API_KEY_NAME": "11111111-1111-1111-1111-111111111111", "CBASE_API_PRIVATE_KEY": b64key}),
        |asked| match asked {
            Asked::SignEs256 { .. } => panic!("an Ed25519 key is never handed to ES256"),
            Asked::Fetch(req) => {
                let token = req.header_value("Authorization").unwrap()[7..].to_string();
                let parts: Vec<&str> = token.split('.').collect();
                let header: Value = serde_json::from_slice(&b64(parts[0])).unwrap();
                assert_eq!(header["alg"], "EdDSA");
                let sig = ed25519_dalek::Signature::from_slice(&b64(parts[2])).unwrap();
                key.verifying_key()
                    .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
                    .expect("the EdDSA JWT verifies");
                ok(fixture("accounts_last_page.json"))
            }
        },
    );
    assert_eq!(out["result"]["isError"], false, "{out}");
}
