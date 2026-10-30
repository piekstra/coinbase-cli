//! The per-request JWT Coinbase's CDP APIs authenticate with.
//!
//! Every call carries `Authorization: Bearer <jwt>`, and the token is bound to
//! the exact request: the `uri` claim is `"<METHOD> <host><path>"`, so a token
//! minted for `GET api.coinbase.com/v2/accounts` cannot be replayed against
//! anything else. Tokens are valid for [`LIFETIME_SECS`], which is why there is
//! no token cache anywhere in this CLI — minting is cheap and a cached token
//! would be expired more often than not.
//!
//! Assembled by hand rather than with `jsonwebtoken`. That crate would work —
//! since 10.0.0 its `Header` has a first-class `nonce` field — but it buys
//! little here and costs two things. Its `EncodingKey::from_ec_pem` accepts
//! **PKCS#8 only** while Coinbase ships **SEC1** (`BEGIN EC PRIVATE KEY`), so
//! every key would need re-encoding first; and `jsonwebtoken 11` internally
//! pins `p256 0.13` / `ed25519-dalek 2.1`, which would put a second major
//! version of both crypto crates into the dependency graph beside the ones used
//! here directly. Signing a JWS is ~40 lines, and doing it in-tree keeps the
//! whole path unit-testable offline — including verifying a token against its
//! own public key, which is the only way to prove any of this without a live
//! request.
//!
//! Two signature algorithms, matching the two key types Coinbase issues:
//! `ES256` (ECDSA P-256 + SHA-256, from a PEM key) and `EdDSA` (Ed25519, from a
//! base64 key). Both produce the fixed-width raw signature JWS wants — for
//! ES256 that is `r || s`, **not** the ASN.1 DER encoding OpenSSL emits by
//! default; getting that wrong is the classic ES256 interop bug and yields a
//! 401 that looks like a bad key.
//!
//! **Prefer an ECDSA key.** Coinbase's own docs say Ed25519 keys are not
//! supported by the Coinbase App API surface and "your authentication attempts
//! may fail", even though Ed25519 is the CDP portal's default and recommended
//! choice everywhere else. EdDSA is implemented here so a key of either type
//! works if that ever changes, and `cbase` warns when an Ed25519 key is stored.
//! <https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/api-key-authentication>

use base64::Engine;
use pk_cli_core::CliError;
use serde_json::json;

/// How long a minted token is valid. Coinbase rejects tokens with a longer
/// window.
pub const LIFETIME_SECS: u64 = 120;

/// The `iss` claim value CDP expects.
pub const ISSUER: &str = "cdp";

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The private half of a CDP API key, in whichever form Coinbase issued it.
pub enum Signer {
    /// ECDSA over NIST P-256, from a PEM key (`-----BEGIN EC PRIVATE KEY-----`
    /// SEC1, or `-----BEGIN PRIVATE KEY-----` PKCS#8).
    Es256(Box<p256::ecdsa::SigningKey>),
    /// Ed25519, from a base64 key: either the 32-byte seed or the 64-byte
    /// `seed || public key` pair Coinbase's download contains.
    EdDsa(Box<ed25519_dalek::SigningKey>),
}

impl Signer {
    /// Detect the key type from its encoding and build a signer.
    ///
    /// PEM means EC; anything else is treated as base64 Ed25519. There is no
    /// ambiguity in practice — the two encodings share no prefix — and
    /// sniffing means the user never has to tell the CLI which kind of key
    /// they pasted.
    pub fn from_private_key(raw: &str) -> Result<Self, CliError> {
        let key = raw.trim();
        if key.contains("-----BEGIN") {
            Self::ec_from_pem(key)
        } else {
            Self::ed25519_from_base64(key)
        }
    }

    fn ec_from_pem(pem: &str) -> Result<Self, CliError> {
        use p256::pkcs8::DecodePrivateKey;
        // Coinbase issues SEC1 ("EC PRIVATE KEY"); PKCS#8 ("PRIVATE KEY") is
        // accepted too, since that is what most conversion tools emit and a
        // user who round-tripped their key through one should not be stuck.
        let secret = if pem.contains("BEGIN EC PRIVATE KEY") {
            p256::SecretKey::from_sec1_pem(pem).map_err(|e| bad_key("SEC1 EC PEM", e))?
        } else {
            p256::SecretKey::from_pkcs8_pem(pem).map_err(|e| bad_key("PKCS#8 PEM", e))?
        };
        Ok(Signer::Es256(Box::new(p256::ecdsa::SigningKey::from(
            &secret,
        ))))
    }

    fn ed25519_from_base64(b64: &str) -> Result<Self, CliError> {
        // Coinbase's Ed25519 download is standard base64 with padding; accept
        // the url-safe and unpadded spellings too rather than fail on a value
        // that was copied through something that re-encoded it.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
            .or_else(|_| B64URL.decode(b64))
            .map_err(|e| {
                CliError::Auth(format!(
                    "the private key is neither a PEM EC key nor valid base64 ({e})"
                ))
            })?;
        let key = match bytes.len() {
            32 => {
                let seed: [u8; 32] = bytes[..32].try_into().expect("length checked");
                ed25519_dalek::SigningKey::from_bytes(&seed)
            }
            64 => {
                // Coinbase's 64-byte form is `seed || public key`.
                // `from_keypair_bytes` checks the two halves agree, so a
                // truncated or spliced copy fails loudly right here instead of
                // producing signatures Coinbase rejects with a 401 that reads
                // like a permissions problem.
                let pair: [u8; 64] = bytes[..64].try_into().expect("length checked");
                ed25519_dalek::SigningKey::from_keypair_bytes(&pair).map_err(|e| {
                    CliError::Auth(format!(
                        "the Ed25519 key's public half does not match its private half ({e}) — \
                         re-download the key from the CDP portal"
                    ))
                })?
            }
            n => {
                return Err(CliError::Auth(format!(
                    "the private key decoded to {n} bytes; an Ed25519 CDP key is 32 or 64"
                )))
            }
        };
        Ok(Signer::EdDsa(Box::new(key)))
    }

    /// The JOSE `alg` value for this key.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Signer::Es256(_) => "ES256",
            Signer::EdDsa(_) => "EdDSA",
        }
    }

    /// Raw JWS signature bytes over the signing input: fixed-width `r || s`
    /// for ES256, the 64-byte Ed25519 signature for EdDSA.
    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        match self {
            Signer::Es256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(signing_input);
                sig.to_bytes().to_vec()
            }
            Signer::EdDsa(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(signing_input).to_bytes().to_vec()
            }
        }
    }
}

/// Mint a bearer token for one request.
///
/// `method` is the upper-case HTTP verb, `host` the bare API host (no scheme),
/// and `path` the path with a leading slash and **no query string** — Coinbase
/// builds the `uri` claim from the path alone, so including `?limit=…` makes
/// the token fail to validate.
pub fn mint(
    signer: &Signer,
    key_id: &str,
    method: &str,
    host: &str,
    path: &str,
    now_secs: u64,
    nonce: &str,
) -> Result<String, CliError> {
    let uri = uri_claim(method, host, path);
    let header = json!({
        "alg": signer.algorithm(),
        "typ": "JWT",
        "kid": key_id,
        "nonce": nonce,
    });
    let claims = json!({
        "sub": key_id,
        "iss": ISSUER,
        "nbf": now_secs,
        "exp": now_secs + LIFETIME_SECS,
        "uri": uri,
    });

    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).map_err(encode_err)?),
        B64URL.encode(serde_json::to_vec(&claims).map_err(encode_err)?),
    );
    let sig = signer.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", B64URL.encode(sig)))
}

/// `"GET api.coinbase.com/v2/accounts"` — method, space, host, path. Any query
/// string is dropped, and the path is normalized to exactly one leading slash.
pub fn uri_claim(method: &str, host: &str, path: &str) -> String {
    let host = host
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let path = path.split('?').next().unwrap_or("");
    let path = path.trim_start_matches('/');
    format!("{} {host}/{path}", method.to_uppercase())
}

/// A fresh 128-bit nonce as lower-case hex, from the OS CSPRNG.
pub fn nonce() -> String {
    use rand::Rng as _;
    let mut bytes = [0u8; 16];
    // `rand::rng()` is a CSPRNG seeded from the OS. Not a plain counter: the
    // nonce is what stops a captured token being replayed within its window.
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn bad_key(kind: &str, e: impl std::fmt::Display) -> CliError {
    CliError::Auth(format!("the private key is not a valid {kind} key ({e})"))
}

fn encode_err(e: serde_json::Error) -> CliError {
    CliError::Other(format!("building the auth token: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey;

    /// A P-256 key generated fresh for each test run. Nothing key-shaped is
    /// ever committed to this repo — a PEM in the tree is both a gitleaks
    /// finding and a bad habit.
    fn throwaway_ec_pem() -> String {
        let secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        secret
            .to_sec1_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encodes")
            .to_string()
    }

    fn throwaway_pkcs8_pem() -> String {
        let secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encodes")
            .to_string()
    }

    fn parts(jwt: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        let bits: Vec<&str> = jwt.split('.').collect();
        assert_eq!(bits.len(), 3, "a JWS compact serialization has three parts");
        let dec = |s: &str| B64URL.decode(s).expect("base64url");
        (
            serde_json::from_slice(&dec(bits[0])).unwrap(),
            serde_json::from_slice(&dec(bits[1])).unwrap(),
            dec(bits[2]),
        )
    }

    #[test]
    fn es256_token_has_the_header_and_claims_coinbase_requires() {
        let signer = Signer::from_private_key(&throwaway_ec_pem()).unwrap();
        let jwt = mint(
            &signer,
            "organizations/o/apiKeys/k",
            "GET",
            "api.coinbase.com",
            "/v2/accounts",
            1_700_000_000,
            "deadbeef",
        )
        .unwrap();
        let (header, claims, sig) = parts(&jwt);

        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "organizations/o/apiKeys/k");
        // The nonce is a *header* parameter, not a claim — the reason this
        // module exists instead of a call into `jsonwebtoken`.
        assert_eq!(header["nonce"], "deadbeef");
        assert!(claims.get("nonce").is_none());

        assert_eq!(claims["sub"], "organizations/o/apiKeys/k");
        assert_eq!(claims["iss"], "cdp");
        assert_eq!(claims["nbf"], 1_700_000_000u64);
        assert_eq!(claims["exp"], 1_700_000_000u64 + LIFETIME_SECS);
        assert_eq!(claims["uri"], "GET api.coinbase.com/v2/accounts");

        // Fixed-width r||s, not ASN.1 DER (which would be ~70 bytes and start
        // with 0x30). This assertion is the whole ES256 interop trap.
        assert_eq!(sig.len(), 64, "ES256 JWS signatures are 64 raw bytes");
    }

    #[test]
    fn es256_signature_verifies_against_the_public_key() {
        let pem = throwaway_ec_pem();
        let signer = Signer::from_private_key(&pem).unwrap();
        let jwt = mint(
            &signer,
            "k",
            "GET",
            "api.coinbase.com",
            "/v2/accounts",
            1,
            "n",
        )
        .unwrap();

        let (input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&B64URL.decode(sig_b64).unwrap()).unwrap();
        let verifying = p256::ecdsa::VerifyingKey::from(&p256::ecdsa::SigningKey::from(
            &p256::SecretKey::from_sec1_pem(&pem).unwrap(),
        ));
        use p256::ecdsa::signature::Verifier as _;
        verifying
            .verify(input.as_bytes(), &sig)
            .expect("the token verifies under its own key");
    }

    /// The 64-byte `seed || public key` blob Coinbase's Ed25519 download
    /// contains, built from a fixed seed so the halves genuinely agree.
    fn ed25519_keypair_b64() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        base64::engine::general_purpose::STANDARD.encode(key.to_keypair_bytes())
    }

    #[test]
    fn eddsa_token_is_signed_with_ed25519() {
        let signer = Signer::from_private_key(&ed25519_keypair_b64()).unwrap();
        assert_eq!(signer.algorithm(), "EdDSA");
        let jwt = mint(
            &signer,
            "k",
            "GET",
            "api.coinbase.com",
            "/v2/accounts",
            1,
            "n",
        )
        .unwrap();
        let (header, _, sig) = parts(&jwt);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn pkcs8_pem_is_accepted_too() {
        let signer = Signer::from_private_key(&throwaway_pkcs8_pem()).unwrap();
        assert_eq!(signer.algorithm(), "ES256");
    }

    /// A PEM envelope with garbage inside, assembled at runtime rather than
    /// written as a literal: a complete `BEGIN…PRIVATE KEY` header sitting in
    /// the source trips gitleaks' `private-key` rule, and adding an allowlist
    /// entry to quiet the scanner in a repo whose entire job is handling real
    /// private keys is a bad trade. Splitting the header defuses it without
    /// weakening the rule.
    fn malformed_pem() -> String {
        let label = "EC PRIVATE KEY";
        format!("-----BEGIN {label}-----\nnope\n-----END {label}-----")
    }

    #[test]
    fn a_bad_key_is_an_auth_error_not_a_panic() {
        let malformed = malformed_pem();
        for junk in [
            malformed.as_str(),
            "not base64 !!!",
            "AAAA", // valid base64, wrong length
        ] {
            assert!(
                matches!(Signer::from_private_key(junk), Err(CliError::Auth(_))),
                "expected an auth error for {junk:?}"
            );
        }
    }

    /// A 64-byte blob whose public half doesn't match its seed is a corrupted
    /// key. Rejecting it here beats signing with it and reading Coinbase's 401
    /// as a permissions problem.
    #[test]
    fn a_mismatched_ed25519_keypair_is_rejected_at_load() {
        let bogus = base64::engine::general_purpose::STANDARD.encode([3u8; 64]);
        assert!(matches!(
            Signer::from_private_key(&bogus),
            Err(CliError::Auth(_))
        ));
    }

    /// The bare 32-byte seed form still loads — there is nothing to
    /// cross-check, and refusing it would reject a valid key.
    #[test]
    fn a_bare_ed25519_seed_is_accepted() {
        let seed = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        assert_eq!(
            Signer::from_private_key(&seed).unwrap().algorithm(),
            "EdDSA"
        );
    }

    #[test]
    fn the_uri_claim_drops_the_scheme_and_query_string() {
        assert_eq!(
            uri_claim("get", "https://api.coinbase.com", "/v2/accounts?limit=100"),
            "GET api.coinbase.com/v2/accounts"
        );
        assert_eq!(
            uri_claim("GET", "api.coinbase.com/", "v2/accounts"),
            "GET api.coinbase.com/v2/accounts"
        );
    }

    #[test]
    fn nonces_do_not_repeat() {
        let a = nonce();
        let b = nonce();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "a repeated nonce defeats the point of having one");
    }
}
