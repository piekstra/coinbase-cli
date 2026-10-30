//! Non-secret settings, in `~/.config/cbase/config.toml`.
//!
//! Nothing identity-bearing is kept here. The CDP API key — *both* halves of
//! it, the key id and the private key — lives in the OS keychain as one blob
//! (see [`crate::credential`]), because the key id embeds the CDP organization
//! UUID and is no more suitable for a plaintext dotfile than the key material
//! itself. Config holds only what is safe to `cat`: which host to talk to and
//! which account a bare command defaults to.

use serde::{Deserialize, Serialize};

/// Keychain account under `piekstra.cbase` holding the CDP API key JSON.
pub const KEYCHAIN_ACCOUNT: &str = "api-key";

/// Coinbase's API host. Both the v2 App API and the v3 Advanced Trade API are
/// served from here.
pub const DEFAULT_BASE_URL: &str = "https://api.coinbase.com";

pub const KNOWN_KEYS: &[&str] = &["base_url", "account"];

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Override the API host (for a proxy or a replay fixture server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Default account UUID for commands that take `--account`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

impl Config {
    pub fn base_url(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string()
    }

    pub fn account(&self) -> Option<String> {
        self.account.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_defaults_and_strips_trailing_slash() {
        assert_eq!(Config::default().base_url(), DEFAULT_BASE_URL);
        let cfg = Config {
            base_url: Some("https://example.test/".into()),
            account: None,
        };
        assert_eq!(cfg.base_url(), "https://example.test");
    }

    /// An empty config must serialize to an empty table, not a wall of nulls —
    /// `config show` renders this straight to the user.
    #[test]
    fn empty_config_serializes_empty() {
        let v = serde_json::to_value(Config::default()).unwrap();
        assert_eq!(v, serde_json::json!({}));
    }
}
