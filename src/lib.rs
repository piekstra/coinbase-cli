//! `cbase` — Coinbase accounts and transaction history, from the command line.
//!
//! The binary in `main.rs` is a thin clap shell over these modules. They are
//! public so the integration tests can exercise the parsers and the JWT signer
//! directly, offline, against hand-authored fixtures.
//!
//! Read-only by construction: nothing here places an order, moves funds, or
//! writes to a Coinbase account. The `api` passthrough refuses every verb but
//! `GET` for that reason. That claim is enforced in
//! [`commands::api`] and must change in the same commit as any first write.

pub mod client;
pub mod commands;
pub mod config;
pub mod credential;
pub mod jwt;
pub mod parse;
