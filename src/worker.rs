//! The MCP tools as a WebAssembly module for the deploy-your-own Cloudflare
//! Worker (cli-common's `connector/`), released as `cbase-mcp-<version>.wasm`
//! and built with `make wasm`.
//!
//! The tools are the ones `cbase mcp` serves ([`crate::mcp::CoinbaseTools`]),
//! over the same client, signer and parsers; only the transport differs: the
//! Worker's `fetch`, and its WebCrypto for ES256
//! ([`pk_cli_mcp::wasm::HostTransport`]). Instructions and auth errors say the
//! key is in the Worker's secrets, not the keychain.
//!
//! The Worker passes its secrets as each call's config, by name, the same
//! names as the CLI's environment variables:
//!
//! | Key | |
//! |---|---|
//! | `CBASE_API_KEY_NAME` | the CDP API key's name (`organizations/…/apiKeys/…`) |
//! | `CBASE_API_PRIVATE_KEY` | its private key: the PEM (literal `\n` escapes and a one-line paste are repaired), or an Ed25519 key's base64 |
//! | `CBASE_BASE_URL` | optional: the API host, `https://api.coinbase.com` by default (a local mock in development) |

use std::cell::RefCell;

use pk_cli_core::CliError;
use pk_cli_mcp::wasm::HostTransport;
use serde_json::Value;

use crate::client::Coinbase;
use crate::config::DEFAULT_BASE_URL;
use crate::credential::{key_from_parts, Credential, ENV_KEY_NAME, ENV_PRIVATE_KEY};
use crate::mcp::{ClientSource, CoinbaseTools};

/// The config key for the API host.
pub const BASE_URL: &str = "CBASE_BASE_URL";

pk_cli_mcp::export_wasm!(tools);

/// The toolset for one call, from the Worker's config. Never fails: without a
/// usable key, each tool call answers an auth error instead, so the tools can
/// be described before any secret is set.
pub fn tools(config: &Value) -> CoinbaseTools<ClientSource<HostTransport>> {
    CoinbaseTools::new(ClientSource::new(client(config)), None)
}

fn client(config: &Value) -> Result<Coinbase<HostTransport>, CliError> {
    let text = |key: &str| {
        config
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
    };
    let blob = key_from_parts(text(ENV_KEY_NAME), text(ENV_PRIVATE_KEY))?.ok_or_else(|| {
        CliError::Auth(format!(
            "no Coinbase API key is configured: the Worker's {ENV_KEY_NAME} and \
             {ENV_PRIVATE_KEY} secrets are not set"
        ))
    })?;
    let base_url = text(BASE_URL).unwrap_or(DEFAULT_BASE_URL).trim();
    Ok(Coinbase::with_transport(
        parsed(&blob)?,
        base_url,
        HostTransport,
    ))
}

thread_local! {
    /// The last key this isolate parsed. An isolate serves many calls, and
    /// parsing a P-256 key derives its public point, a scalar multiplication
    /// that costs as much CPU as a signature. Keyed on the key itself, so a
    /// rotated secret simply misses.
    static PARSED: RefCell<Option<(String, Credential)>> = const { RefCell::new(None) };
}

fn parsed(blob: &str) -> Result<Credential, CliError> {
    if let Some(hit) = PARSED.with_borrow(|p| {
        p.as_ref()
            .filter(|(key, _)| key == blob)
            .map(|(_, cred)| cred.clone())
    }) {
        return Ok(hit);
    }
    let cred = Credential::parse(blob)?;
    PARSED.set(Some((blob.to_string(), cred.clone())));
    Ok(cred)
}
