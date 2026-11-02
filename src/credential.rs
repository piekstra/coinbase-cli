//! The CDP API key: what it looks like, and how it gets into this process.
//!
//! Coinbase hands you a JSON file when you create a key in the CDP portal. Two
//! shapes are in circulation, because Coinbase changed the default key type:
//!
//! ```json
//! { "name": "organizations/<org-uuid>/apiKeys/<key-uuid>",
//!   "privateKey": "-----BEGIN EC PRIVATE KEY-----\n<base64 key material>\n-----END EC PRIVATE KEY-----\n" }
//! ```
//!
//! ```json
//! { "id": "<key-uuid>", "privateKey": "<base64 Ed25519 key>" }
//! ```
//!
//! Both are accepted verbatim: the whole file is what the user pipes in, so
//! there is no step where they hand-extract a private key onto a command line.
//! The blob is stored in the OS keychain as-is and re-parsed at point of use.
//!
//! The private key never leaves this module's callers as text: [`Credential`]
//! exposes only a signer. `Debug` is implemented by hand so a stray `{:?}`
//! cannot print key material.

use std::fmt;

use pk_cli_core::CliError;
#[cfg(feature = "native")]
use pk_cli_secrets::{CredentialStore, Secret};
use serde::Deserialize;

#[cfg(feature = "native")]
use crate::config::KEYCHAIN_ACCOUNT;
use crate::jwt::Signer;

/// The CDP API key's name (`organizations/<org>/apiKeys/<key>`, or a bare key
/// id), for a run that takes its key from the environment rather than the
/// keychain. Claude Desktop's `.mcpb` passes its `sensitive` settings this way,
/// and the Worker module reads the Worker secrets of the same names.
pub const ENV_KEY_NAME: &str = "CBASE_API_KEY_NAME";

/// The CDP private key that goes with [`ENV_KEY_NAME`]: the PEM, or an Ed25519
/// key's base64.
pub const ENV_PRIVATE_KEY: &str = "CBASE_API_PRIVATE_KEY";

/// Where the key in use came from.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// [`ENV_KEY_NAME`] and [`ENV_PRIVATE_KEY`].
    Env,
    /// The OS keychain (`piekstra.cbase`, account `api-key`).
    Keychain,
}

/// The key to sign with: the environment first, then the keychain (the
/// family's precedence, DESIGN.md §1.7). With both variables set the keychain
/// is never opened, so a host that passes the key in the environment (a
/// Claude Desktop extension) raises no keychain prompt at all.
#[cfg(feature = "native")]
pub fn resolve_key(creds: &CredentialStore) -> Result<Option<(Secret, KeySource)>, CliError> {
    if let Some(key) = key_from_env()? {
        return Ok(Some((key, KeySource::Env)));
    }
    Ok(read_stored_key(creds)?.map(|k| (k, KeySource::Keychain)))
}

/// The key from [`ENV_KEY_NAME`] + [`ENV_PRIVATE_KEY`], as the same JSON blob
/// the keychain holds, or `None` when neither is set. One without the other is
/// an auth error naming the missing one: falling back to the keychain would
/// sign with a key the caller did not choose.
#[cfg(feature = "native")]
pub fn key_from_env() -> Result<Option<Secret>, CliError> {
    key_from_vars(env_value(ENV_KEY_NAME)?, env_value(ENV_PRIVATE_KEY)?)
}

/// A variable that is set but not UTF-8 is an auth error naming it, not
/// "unset": treating it as unset would fall through to the keychain.
#[cfg(feature = "native")]
fn env_value(name: &str) -> Result<Option<String>, CliError> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::Auth(format!(
            "{name} is set but is not valid UTF-8; set it to the value from the CDP key file"
        ))),
    }
}

#[cfg(feature = "native")]
fn key_from_vars(
    name: Option<String>,
    private_key: Option<String>,
) -> Result<Option<Secret>, CliError> {
    match key_from_parts(name.as_deref(), private_key.as_deref()) {
        Ok(blob) => Ok(blob.map(Secret::new)),
        Err(CliError::Auth(m)) => Err(CliError::Auth(format!(
            "{m} to use a key from the environment, or neither to use the keychain"
        ))),
        Err(e) => Err(e),
    }
}

/// The key blob [`Credential::parse`] reads, from a key name and private key
/// held apart: [`ENV_KEY_NAME`] and [`ENV_PRIVATE_KEY`] in the environment
/// natively, the Worker secrets of the same names in the module. `None` when
/// neither is set; one without the other is an auth error naming the missing
/// one. The private key is repaired of what a settings field does to a PEM.
pub fn key_from_parts(
    name: Option<&str>,
    private_key: Option<&str>,
) -> Result<Option<String>, CliError> {
    let present = |v: Option<&str>| v.is_some_and(|s| !s.trim().is_empty());
    match (present(name), present(private_key)) {
        (false, false) => Ok(None),
        (true, false) => Err(CliError::Auth(format!(
            "{ENV_KEY_NAME} is set but {ENV_PRIVATE_KEY} is not — set both"
        ))),
        (false, true) => Err(CliError::Auth(format!(
            "{ENV_PRIVATE_KEY} is set but {ENV_KEY_NAME} is not — set both"
        ))),
        (true, true) => {
            let blob = serde_json::json!({
                "name": name.unwrap_or_default().trim(),
                "privateKey": normalize_private_key(private_key.unwrap_or_default()),
            });
            Ok(Some(blob.to_string()))
        }
    }
}

/// Undo what a settings field does to a multi-line PEM: a value copied out of
/// the key's JSON file carries literal `\n` escapes, and a single-line text
/// box turns the line breaks into spaces. Either way the header, the base64
/// body and the footer are recovered and the body re-wrapped at 64 columns. An
/// Ed25519 key (bare base64) only loses surrounding whitespace.
fn normalize_private_key(raw: &str) -> String {
    let unescaped = raw.trim().replace("\\n", "\n");
    let Some(begin) = unescaped.find("-----BEGIN ") else {
        return unescaped;
    };
    let Some(header_end) = unescaped[begin + 11..]
        .find("-----")
        .map(|i| begin + 11 + i + 5)
    else {
        return unescaped;
    };
    let Some(footer) = unescaped[header_end..]
        .find("-----END ")
        .map(|i| header_end + i)
    else {
        return unescaped;
    };
    let footer_end = unescaped[footer + 9..]
        .find("-----")
        .map(|i| footer + 9 + i + 5)
        .unwrap_or(unescaped.len());
    let header = &unescaped[begin..header_end];
    let body: Vec<char> = unescaped[header_end..footer]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    // Base64 is ASCII. Anything else (a pasted smart quote) is not a PEM this
    // can repair: hand it on unchanged, for the parser to reject as it is.
    if !body.iter().all(char::is_ascii_graphic) {
        return unescaped;
    }
    let footer = &unescaped[footer..footer_end];
    let mut pem = String::from(header);
    pem.push('\n');
    for line in body.chunks(64) {
        pem.extend(line);
        pem.push('\n');
    }
    pem.push_str(footer);
    pem.push('\n');
    pem
}

/// Read the stored key, mapping an unusable keychain onto the auth contract.
///
/// `pk-cli-secrets` reports a missing or locked backend as `CliError::Keychain`
/// (exit 1, "generic"). For a command that is trying to authenticate a request,
/// exit **3** is the more useful answer: the caller could not be authenticated,
/// and a driver branching on 3 gets a message naming the actual cause instead
/// of a generic failure it can only give up on.
///
/// The common way to hit this is a headless Linux host with no D-Bus secret
/// service running — which is exactly what CI is, and how this was found.
#[cfg(feature = "native")]
pub fn read_stored_key(creds: &CredentialStore) -> Result<Option<Secret>, CliError> {
    match creds.get(KEYCHAIN_ACCOUNT) {
        Err(CliError::Keychain(msg)) => Err(CliError::Auth(keychain_unavailable(&msg))),
        other => other,
    }
}

/// The same read, but for `auth status`, which SPEC v1 §1.2 requires to answer
/// even when logged out — and therefore even when the keychain itself is
/// unreachable. Returns the credential (if any) plus a diagnostic to print,
/// rather than failing.
#[cfg(feature = "native")]
pub fn peek_stored_key(creds: &CredentialStore) -> (Option<Secret>, Option<String>) {
    match creds.get(KEYCHAIN_ACCOUNT) {
        Ok(v) => (v, None),
        Err(CliError::Keychain(msg)) => (None, Some(keychain_unavailable(&msg))),
        Err(e) => (None, Some(e.to_string())),
    }
}

/// Every auth error names the command that fixes it — a driver branching on
/// exit 3 should never have to guess the next step. Here the remedy is two
/// parts: make a keychain available, then store the key.
#[cfg(feature = "native")]
fn keychain_unavailable(msg: &str) -> String {
    format!(
        "the OS keychain is unavailable, so the API key could not be read ({msg}). \
         On a headless Linux host this usually means no D-Bus secret service is running; \
         start one (e.g. gnome-keyring), then store a key with \
         `cbase auth set-credential --stdin < cdp_api_key.json`."
    )
}

/// A parsed CDP API key: the id that goes in the JWT's `kid`/`sub`, and a
/// signer over the private half.
///
/// `Clone`, so the Worker module parses a key once per isolate (parsing a
/// P-256 key derives its public point) and hands each call a copy.
#[derive(Clone)]
pub struct Credential {
    /// The key identifier. Either the full
    /// `organizations/{org}/apiKeys/{key}` resource name or a bare UUID,
    /// exactly as Coinbase issued it — it is echoed into the JWT untouched.
    pub key_id: String,
    signer: Signer,
}

/// The on-disk/on-keychain JSON, with the field aliases Coinbase's own
/// examples and downloads have used over time.
#[derive(Deserialize)]
struct KeyFile {
    #[serde(alias = "keyName", alias = "apiKeyName", alias = "api_key_name")]
    name: Option<String>,
    #[serde(alias = "keyId", alias = "api_key_id")]
    id: Option<String>,
    #[serde(alias = "privateKey", alias = "secret", alias = "api_secret")]
    private_key: Option<String>,
}

impl Credential {
    /// Parse the stored key blob.
    ///
    /// Errors are [`CliError::Auth`] (exit 3) rather than `Usage`: by the time
    /// this runs the input came from the keychain, so a bad value means the
    /// stored credential is wrong, which is an auth problem the caller fixes
    /// with `cbase auth set-credential --overwrite`.
    pub fn parse(blob: &str) -> Result<Self, CliError> {
        let raw = blob.trim();
        if raw.is_empty() {
            return Err(CliError::Auth(
                "the stored CDP API key is empty — re-run `cbase auth set-credential`".into(),
            ));
        }
        let file: KeyFile = serde_json::from_str(raw).map_err(|e| {
            CliError::Auth(format!(
                "the stored credential is not a CDP API key JSON file ({e}) — pipe the file \
                 Coinbase gave you into `cbase auth set-credential --stdin --overwrite`"
            ))
        })?;

        let key_id = file
            .name
            .or(file.id)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                CliError::Auth(
                    "the CDP API key JSON has no `name` or `id` field — it does not look like a \
                     key downloaded from the CDP portal"
                        .into(),
                )
            })?;

        let private_key = file
            .private_key
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                CliError::Auth("the CDP API key JSON has no `privateKey` field".into())
            })?;

        Ok(Self {
            key_id,
            signer: Signer::from_private_key(&private_key)?,
        })
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// The key id with the CDP organization UUID masked, for display. The id
    /// is not a secret, but it identifies the account and there is no reason to
    /// splash it across a terminal or a log.
    pub fn masked_key_id(&self) -> String {
        mask_key_id(&self.key_id)
    }
}

/// `organizations/<uuid>/apiKeys/<uuid>` → `organizations/…/apiKeys/<last 4>`;
/// a bare uuid → `…<last 4>`.
fn mask_key_id(id: &str) -> String {
    let tail = |s: &str| {
        let n = s.chars().count();
        s.chars().skip(n.saturating_sub(4)).collect::<String>()
    };
    match id.rsplit_once('/') {
        Some((prefix, last)) => {
            let head = prefix.split('/').next().unwrap_or("organizations");
            format!("{head}/…/…{}", tail(last))
        }
        None => format!("…{}", tail(id)),
    }
}

// Hand-written so key material can never reach a log or a panic message.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("key_id", &self.masked_key_id())
            .field("signer", &self.signer.algorithm())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A P-256 key generated fresh per test run. No key-shaped bytes are ever
    /// committed to this repo — a PEM in the tree is a gitleaks finding and a
    /// habit worth not forming, even for a key that authenticates to nothing.
    fn throwaway_pem() -> String {
        use p256::elliptic_curve::Generate as _;
        p256::SecretKey::generate_from_rng(&mut rand::rng())
            .to_sec1_pem(p256::pkcs8::LineEnding::LF)
            .expect("PEM encodes")
            .to_string()
    }

    fn ec_key_file() -> String {
        serde_json::json!({
            "name": "organizations/00000000-0000-0000-0000-000000000000/apiKeys/11111111-1111-1111-1111-111111111111",
            "privateKey": throwaway_pem(),
        })
        .to_string()
    }

    #[test]
    fn parses_the_ec_key_file_shape() {
        let c = Credential::parse(&ec_key_file()).expect("EC key parses");
        assert!(c.key_id.starts_with("organizations/"));
        assert_eq!(c.signer().algorithm(), "ES256");
    }

    #[test]
    fn accepts_the_bare_id_shape_used_by_ed25519_keys() {
        // 64 bytes of `seed || public key`, base64 — the Ed25519 download
        // shape. Built from a real keypair because the halves are cross-checked.
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let blob = serde_json::json!({
            "id": "11111111-1111-1111-1111-111111111111",
            "privateKey": base64_std(&key.to_keypair_bytes()),
        })
        .to_string();
        let c = Credential::parse(&blob).expect("Ed25519 key parses");
        assert_eq!(c.signer().algorithm(), "EdDSA");
    }

    #[test]
    fn accepts_the_camelcase_aliases() {
        let blob = serde_json::json!({
            "keyName": "organizations/o/apiKeys/k",
            "privateKey": throwaway_pem(),
        })
        .to_string();
        assert!(Credential::parse(&blob).is_ok());
    }

    #[test]
    fn rejects_junk_with_an_auth_error_not_a_panic() {
        for junk in ["", "   ", "not json", "{}", r#"{"name":"x"}"#] {
            match Credential::parse(junk) {
                Err(CliError::Auth(_)) => {}
                other => panic!("expected an auth error for {junk:?}, got {other:?}"),
            }
        }
    }

    /// The whole point of the hand-written `Debug`: no key material, ever.
    #[test]
    fn debug_output_hides_the_key() {
        let c = Credential::parse(&ec_key_file()).unwrap();
        let shown = format!("{c:?}");
        assert!(!shown.contains("BEGIN"), "debug leaked the PEM: {shown}");
        assert!(!shown.contains("PRIVATE"), "debug leaked the PEM: {shown}");
        assert!(
            !shown.contains("00000000-0000-0000-0000-000000000000"),
            "debug leaked the org id: {shown}"
        );
    }

    #[test]
    fn masking_keeps_only_a_tail() {
        let masked = mask_key_id("organizations/abc/apiKeys/deadbeef");
        assert!(masked.contains("beef"));
        assert!(!masked.contains("abc"));
        assert!(!masked.contains("dead"));
        assert_eq!(mask_key_id("abcdefgh"), "…efgh");
    }

    /// The two ways a settings field mangles a PEM, plus the clean one: all
    /// three must parse to the same working key.
    #[test]
    fn a_private_key_from_the_environment_survives_settings_fields() {
        let pem = throwaway_pem();
        let escaped = pem.replace('\n', "\\n");
        let one_line = pem.replace('\n', " ");
        for raw in [pem.clone(), escaped, one_line] {
            let blob = key_from_vars(Some("organizations/o/apiKeys/k".into()), Some(raw.clone()))
                .expect("both set")
                .expect("a key");
            let c = Credential::parse(blob.expose())
                .unwrap_or_else(|e| panic!("{raw:?} did not parse: {e}"));
            assert_eq!(c.signer().algorithm(), "ES256");
            assert_eq!(c.key_id, "organizations/o/apiKeys/k");
        }
    }

    #[test]
    fn a_pem_with_non_ascii_in_its_body_is_passed_on_unchanged() {
        let pem = throwaway_pem().replacen("\n", "\n\u{201c}", 2);
        assert_eq!(normalize_private_key(&pem), pem.trim());
        let blob = key_from_vars(Some("organizations/o/apiKeys/k".into()), Some(pem))
            .unwrap()
            .unwrap();
        assert!(Credential::parse(blob.expose()).is_err());
    }

    #[test]
    fn an_ed25519_key_from_the_environment_is_only_trimmed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let b64 = base64_std(&key.to_keypair_bytes());
        assert_eq!(normalize_private_key(&format!("  {b64}\n")), b64);
    }

    #[test]
    fn half_an_environment_key_is_an_auth_error_naming_the_missing_half() {
        assert!(key_from_vars(None, None).unwrap().is_none());
        assert!(key_from_vars(Some(" ".into()), Some(String::new()))
            .unwrap()
            .is_none());
        match key_from_vars(Some("organizations/o/apiKeys/k".into()), None) {
            Err(CliError::Auth(m)) => assert!(m.contains(ENV_PRIVATE_KEY), "{m}"),
            other => panic!("expected an auth error, got {other:?}"),
        }
        match key_from_vars(None, Some("x".into())) {
            Err(CliError::Auth(m)) => assert!(m.contains(ENV_KEY_NAME), "{m}"),
            other => panic!("expected an auth error, got {other:?}"),
        }
    }

    /// The Worker's half: the same repair and the same pairing rule, with no
    /// word about a keychain the Worker does not have.
    #[test]
    fn parts_held_apart_make_one_key_blob() {
        let pem = throwaway_pem().replace('\n', "\\n");
        let blob = key_from_parts(Some(" organizations/o/apiKeys/k "), Some(&pem))
            .unwrap()
            .unwrap();
        let c = Credential::parse(&blob).unwrap();
        assert_eq!(c.key_id, "organizations/o/apiKeys/k");
        assert_eq!(c.signer().algorithm(), "ES256");
        assert!(key_from_parts(None, Some("  ")).unwrap().is_none());
        match key_from_parts(Some("k"), None) {
            Err(CliError::Auth(m)) => {
                assert!(m.ends_with("— set both"), "{m}");
                assert!(!m.contains("keychain"), "{m}");
            }
            other => panic!("expected an auth error, got {other:?}"),
        }
    }

    fn base64_std(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
