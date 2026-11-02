//! `cbase` — Coinbase accounts and transaction history, from the command line.
//!
//! The binary in `main.rs` is a thin clap shell over these modules. They are
//! public so the integration tests can exercise the parsers and the JWT signer
//! directly, offline, against hand-authored fixtures.
//!
//! Read-only by construction: nothing here places an order, moves funds, or
//! writes to a Coinbase account. The `api` passthrough refuses every verb but
//! `GET` for that reason. That claim is enforced in `commands::api` and must
//! change in the same commit as any first write. The MCP tools in [`mcp`] are
//! reads over the same client, served by `cbase mcp` natively and by the
//! WebAssembly module in [`worker`] (feature `wasm`) in a deploy-your-own
//! Cloudflare Worker.
//!
//! Features: `native` (default) is everything the terminal binary needs
//! (keychain, clap, self-update, blocking HTTP, the stdio MCP server); `wasm`
//! is the Worker module. The library builds for `wasm32-unknown-unknown`
//! with `--no-default-features --features wasm`.

#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
compile_error!(
    "on wasm32, build with `--no-default-features --features wasm`: the module's clock and \
     randomness come from the Worker through pk-cli-mcp's host"
);

pub mod client;
#[cfg(feature = "native")]
pub mod commands;
pub mod config;
pub mod credential;
pub mod jwt;
pub mod mcp;
pub mod parse;
#[cfg(feature = "wasm")]
pub mod worker;
