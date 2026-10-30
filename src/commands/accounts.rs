//! `cbase accounts list` — every wallet on the key's Coinbase account, with
//! balances.
//!
//! This is also the discovery command for `transactions list --account <id>`:
//! the `id` column is exactly the value that flag wants.

use clap::Subcommand;
use pk_cli_core::CliError;
use pk_cli_utility::Paged;

use super::{Ctx, ACCOUNTS};
use crate::parse;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List wallets and balances (crypto-account-list/v1).
    #[command(visible_alias = "ls")]
    List(ListArgs),
}

/// Deliberately **not** the shared `RangeArgs`.
///
/// `RangeArgs` bundles `--limit` with `--since`/`--until`, and a wallet is not
/// a dated record — there is nothing for a date range to filter. Flattening it
/// here would put two flags on `--help` that parse, validate, and then silently
/// do nothing, which is worse than not offering them. `transactions list`, where
/// the dates are meaningful, uses `RangeArgs` as intended.
#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Maximum wallets to return.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Include wallets with a zero balance. Coinbase returns an account for
    /// every asset it has ever supported for you, so the default hides the
    /// empty ones — otherwise a handful of real holdings are lost in a list of
    /// hundreds of zeroes.
    #[arg(long)]
    pub all: bool,
}

pub fn run(ctx: &Ctx, cmd: &Cmd) -> Result<(), CliError> {
    let Cmd::List(args) = cmd;

    let rows = ctx
        .client()?
        .get_all(ACCOUNTS, &[], zero_filtered_limit(args.all, args.limit))?;
    let mut accounts = parse::accounts(&rows);
    if !args.all {
        accounts.retain(|a| !is_zero(&a.balance.amount));
    }
    if let Some(n) = args.limit {
        accounts.truncate(n as usize);
    }

    Paged::new("crypto-account", accounts).emit(ctx.common.json);
    Ok(())
}

/// `--limit` counts records the user will *see*, but the zero-balance filter
/// runs after paging — so when it is active the fetch must not stop at the
/// limit or a page of empty wallets would swallow the whole result.
fn zero_filtered_limit(all: bool, limit: Option<u32>) -> Option<u32> {
    if all {
        limit
    } else {
        None
    }
}

/// True for `"0"`, `"0.00000000"`, `"-0.0"`, and friends — without parsing a
/// float, which would round a dust balance to zero and hide it.
fn is_zero(amount: &str) -> bool {
    let s = amount.trim().trim_start_matches(['+', '-']);
    !s.is_empty() && s.chars().all(|c| c == '0' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_detection_does_not_go_through_a_float() {
        for z in ["0", "0.0", "0.00000000", "-0.00000000", "+0", " 0.00 "] {
            assert!(is_zero(z), "{z} should read as zero");
        }
        for nz in ["0.00000001", "1", "-0.5", "10.00", ""] {
            assert!(!is_zero(nz), "{nz} should not read as zero");
        }
    }

    #[test]
    fn the_fetch_limit_is_dropped_when_zero_balances_are_filtered_out() {
        // Filtering on: fetch everything, then trim.
        assert_eq!(zero_filtered_limit(false, Some(5)), None);
        // --all: the limit can be pushed down to the fetch.
        assert_eq!(zero_filtered_limit(true, Some(5)), Some(5));
        assert_eq!(zero_filtered_limit(true, None), None);
    }
}
