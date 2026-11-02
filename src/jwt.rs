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
use pk_cli_core::transport::PlatformSigner;
use pk_cli_core::CliError;
use serde_json::json;
use zeroize::Zeroizing;

/// How long a minted token is valid. Coinbase rejects tokens with a longer
/// window.
pub const LIFETIME_SECS: u64 = 120;

/// The `iss` claim value CDP expects.
pub const ISSUER: &str = "cdp";

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The private half of a CDP API key, in whichever form Coinbase issued it.
///
/// `Clone` so a long-lived host (a Worker isolate) can parse the key once and
/// hand each call a copy: loading a P-256 key derives its public point, a
/// scalar multiplication as costly as a signature.
#[derive(Clone)]
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

    /// The EC key as PKCS#8 DER, for a platform signer (WebCrypto's
    /// `importKey("pkcs8", …)`), wiped on drop. `None` for an Ed25519 key.
    ///
    /// The scalar alone, without the optional public key, so this is a copy
    /// and not a scalar multiplication: the platform derives the public half
    /// on import, natively.
    fn es256_pkcs8_der(&self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Signer::Es256(k) => {
                let scalar: Zeroizing<[u8; 32]> = Zeroizing::new(k.to_bytes().into());
                let mut der = Zeroizing::new(Vec::with_capacity(P256_PKCS8_PREFIX.len() + 32));
                der.extend_from_slice(&P256_PKCS8_PREFIX);
                der.extend_from_slice(scalar.as_slice());
                Some(der)
            }
            Signer::EdDsa(_) => None,
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

/// What a token says besides its key: the request it is for, when, and its
/// nonce.
///
/// `method` is the upper-case HTTP verb, `host` the bare API host (no scheme),
/// and `path` the path with a leading slash and **no query string** — Coinbase
/// builds the `uri` claim from the path alone, so including `?limit=…` makes
/// the token fail to validate.
#[derive(Debug, Clone, Copy)]
pub struct Claims<'a> {
    pub key_id: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    /// Seconds since the Unix epoch: `nbf`, and `exp` after [`LIFETIME_SECS`].
    pub now_secs: u64,
    pub nonce: &'a str,
}

/// An ES256 JWS signature: `r || s`, 32 bytes each.
const ES256_SIGNATURE_LEN: usize = 64;

/// Mint a bearer token for one request.
///
/// An ES256 signature is asked of `platform` first (WebCrypto in the Worker,
/// native code where WebAssembly P-256 would cost most of a request's CPU).
/// When the platform has no signer (`None`), fails, or answers with anything
/// but a 64-byte `r || s`, this crate signs instead: the token is equally
/// valid. `warn` hears why when the platform tried and the answer was unusable.
/// EdDSA is always signed here.
pub async fn mint(
    signer: &Signer,
    platform: &impl PlatformSigner,
    claims: &Claims<'_>,
    warn: fn(&str),
) -> Result<String, CliError> {
    let input = signing_input(signer, claims)?;
    let asked = match signer.es256_pkcs8_der() {
        Some(der) => platform.sign_es256(&der, input.as_bytes()).await,
        None => None,
    };
    let signature = match asked {
        Some(Ok(sig)) if sig.len() == ES256_SIGNATURE_LEN => sig,
        Some(Ok(sig)) => {
            warn(&format!(
                "the platform's ES256 signature was {} bytes, not {ES256_SIGNATURE_LEN}; \
                 signing in-process instead",
                sig.len()
            ));
            signer.sign(input.as_bytes())
        }
        Some(Err(e)) => {
            warn(&format!(
                "the platform could not sign ES256 ({e}); signing in-process instead"
            ));
            signer.sign(input.as_bytes())
        }
        None => signer.sign(input.as_bytes()),
    };
    Ok(assemble(&input, &signature))
}

/// The JWS signing input, `base64url(header).base64url(claims)`: everything
/// but the signature. The header's `alg` is `signer`'s.
fn signing_input(signer: &Signer, c: &Claims<'_>) -> Result<String, CliError> {
    let uri = uri_claim(c.method, c.host, c.path);
    let header = json!({
        "alg": signer.algorithm(),
        "typ": "JWT",
        "kid": c.key_id,
        "nonce": c.nonce,
    });
    let claims = json!({
        "sub": c.key_id,
        "iss": ISSUER,
        "nbf": c.now_secs,
        "exp": c.now_secs + LIFETIME_SECS,
        "uri": uri,
    });
    Ok(format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).map_err(encode_err)?),
        B64URL.encode(serde_json::to_vec(&claims).map_err(encode_err)?),
    ))
}

/// The compact JWS: the signing input, a dot, the base64url signature.
fn assemble(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", B64URL.encode(signature))
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

/// A fresh 128-bit nonce as lower-case hex, from `fill_random`, which must
/// be a CSPRNG (the platform's: see `client::Platform`). Not a plain counter:
/// the nonce is what stops a captured token being replayed within its window.
pub fn nonce(fill_random: fn(&mut [u8])) -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The DER of a P-256 PKCS#8 `PrivateKeyInfo` up to its 32-byte scalar
/// (RFC 5208, RFC 5915), the `ECPrivateKey` without its optional parameters
/// and public key.
const P256_PKCS8_PREFIX: [u8; 35] = [
    0x30, 0x41, // PrivateKeyInfo SEQUENCE, 65 bytes
    0x02, 0x01, 0x00, // version 0
    0x30, 0x13, // AlgorithmIdentifier SEQUENCE, 19 bytes
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
    0x04, 0x27, // privateKey OCTET STRING, 39 bytes
    0x30, 0x25, // ECPrivateKey SEQUENCE, 37 bytes
    0x02, 0x01, 0x01, // version 1
    0x04, 0x20, // privateKey OCTET STRING, 32 bytes: the scalar follows
];

fn bad_key(kind: &str, e: impl std::fmt::Display) -> CliError {
    CliError::Auth(format!("the private key is not a valid {kind} key ({e})"))
}

fn encode_err(e: serde_json::Error) -> CliError {
    CliError::Other(format!("building the auth token: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    use p256::ecdsa::signature::Verifier as _;
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey;

    /// A platform with no signer of its own, as natively.
    struct NoPlatform;

    impl PlatformSigner for NoPlatform {
        async fn sign_es256(&self, _: &[u8], _: &[u8]) -> Option<Result<Vec<u8>, CliError>> {
            None
        }
    }

    /// A platform that gives `answer` to every ES256 request, and counts them.
    struct Answers(Option<Result<Vec<u8>, CliError>>, Cell<u32>);

    impl PlatformSigner for Answers {
        async fn sign_es256(&self, _: &[u8], _: &[u8]) -> Option<Result<Vec<u8>, CliError>> {
            self.1.set(self.1.get() + 1);
            self.0.clone()
        }
    }

    thread_local! {
        static WARNED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn record_warning(line: &str) {
        WARNED.with_borrow_mut(|w| w.push(line.to_string()));
    }

    fn no_warning(line: &str) {
        panic!("unexpected warning: {line}");
    }

    fn at(path: &str, now_secs: u64) -> Claims<'_> {
        Claims {
            key_id: "organizations/o/apiKeys/k",
            method: "GET",
            host: "api.coinbase.com",
            path,
            now_secs,
            nonce: "deadbeef",
        }
    }

    fn mint_with(
        signer: &Signer,
        platform: &impl PlatformSigner,
        claims: &Claims<'_>,
        warn: fn(&str),
    ) -> String {
        pk_cli_core::block_on(mint(signer, platform, claims, warn)).unwrap()
    }

    fn mint_here(signer: &Signer, claims: &Claims<'_>) -> String {
        mint_with(signer, &NoPlatform, claims, no_warning)
    }

    fn verifies_under(pem: &str, jwt: &str) -> bool {
        let (input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let Ok(sig) = p256::ecdsa::Signature::from_slice(&B64URL.decode(sig_b64).unwrap()) else {
            return false;
        };
        let verifying = p256::ecdsa::VerifyingKey::from(&p256::ecdsa::SigningKey::from(
            &p256::SecretKey::from_sec1_pem(pem).unwrap(),
        ));
        verifying.verify(input.as_bytes(), &sig).is_ok()
    }

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
        let jwt = mint_here(&signer, &at("/v2/accounts", 1_700_000_000));
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
        let jwt = mint_here(&signer, &at("/v2/accounts", 1));
        assert!(
            verifies_under(&pem, &jwt),
            "the token verifies under its own key"
        );
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
        // The platform is never asked for an EdDSA signature.
        let platform = Answers(Some(Ok(vec![7; 64])), Cell::new(0));
        let jwt = mint_with(&signer, &platform, &at("/v2/accounts", 1), no_warning);
        assert_eq!(platform.1.get(), 0);
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

    /// The header's `alg` is always the signer's own.
    #[test]
    fn the_signing_input_names_the_signers_algorithm() {
        let es = Signer::from_private_key(&throwaway_ec_pem()).unwrap();
        let ed = Signer::from_private_key(&ed25519_keypair_b64()).unwrap();
        for (signer, alg) in [(&es, "ES256"), (&ed, "EdDSA")] {
            let input = signing_input(signer, &at("/p", 5)).unwrap();
            let (header, claims, _) = parts(&assemble(&input, &[0u8; 64]));
            assert_eq!(header["alg"], alg);
            assert_eq!(claims["uri"], "GET api.coinbase.com/p");
        }
    }

    /// A 64-byte answer from the platform is the token's signature.
    #[test]
    fn the_platforms_es256_signature_is_used() {
        let signer = Signer::from_private_key(&throwaway_ec_pem()).unwrap();
        let platform = Answers(Some(Ok(vec![7; 64])), Cell::new(0));
        let jwt = mint_with(&signer, &platform, &at("/v2/accounts", 1), no_warning);
        assert_eq!(platform.1.get(), 1);
        assert_eq!(parts(&jwt).2, vec![7; 64]);
    }

    /// No platform signer, a failure, or an answer that is not a 64-byte
    /// `r || s` (DER, say, or truncated): the token is signed here and
    /// verifies; only an unusable answer is worth a warning.
    #[test]
    fn the_token_is_signed_here_when_the_platforms_answer_is_unusable() {
        for (answer, warns) in [
            (None, false),
            (
                Some(Err(CliError::Upstream("DataError: bad key".into()))),
                true,
            ),
            (Some(Ok(vec![0x30; 70])), true),
            (Some(Ok(vec![7; 32])), true),
        ] {
            let pem = throwaway_ec_pem();
            let signer = Signer::from_private_key(&pem).unwrap();
            let platform = Answers(answer.clone(), Cell::new(0));
            WARNED.take();
            let jwt = mint_with(&signer, &platform, &at("/v2/accounts", 1), record_warning);
            assert_eq!(platform.1.get(), 1, "{answer:?}");
            assert!(verifies_under(&pem, &jwt), "{answer:?}");
            let warned = WARNED.take();
            assert_eq!(warned.len(), usize::from(warns), "{answer:?}: {warned:?}");
            assert!(
                warned.iter().all(|w| w.contains("signing in-process")),
                "{warned:?}"
            );
        }
    }

    /// What WebCrypto imports: the same key, so its signatures verify under
    /// the key's own public half.
    #[test]
    fn the_pkcs8_der_is_the_same_ec_key() {
        use p256::pkcs8::DecodePrivateKey;
        let pem = throwaway_ec_pem();
        let signer = Signer::from_private_key(&pem).unwrap();
        let der = signer.es256_pkcs8_der().expect("an EC key exports");
        assert_eq!(der.len(), 67, "the scalar without its public point");
        let back = p256::SecretKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(back, p256::SecretKey::from_sec1_pem(&pem).unwrap());
        let ed = Signer::from_private_key(&ed25519_keypair_b64()).unwrap();
        assert!(ed.es256_pkcs8_der().is_none());
    }

    #[test]
    fn nonces_do_not_repeat() {
        fn os_random(buf: &mut [u8]) {
            use rand::Rng as _;
            rand::rng().fill_bytes(buf);
        }
        let a = nonce(os_random);
        let b = nonce(os_random);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "a repeated nonce defeats the point of having one");
    }
}
