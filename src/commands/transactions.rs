//! `cbase transactions list --account <id>` — one wallet's ledger.
//!
//! This is the command the tax work is actually for: buys, sells, sends,
//! receives, converts, and rewards, each with the asset quantity and Coinbase's
//! own fiat valuation, which together are what a Form 8949 line needs.
//!
//! `--since`/`--until` filter **client-side**. The v2 transactions endpoint
//! publishes no date parameters (see `docs/api.md`), so a bounded query still
//! pages the whole ledger and discards what falls outside. That is a real cost
//! on a long history, and the reason `--limit` exists.

use clap::Subcommand;
use pk_cli_core::CliError;
use pk_cli_utility::{Paged, RangeArgs};

use super::{account_transactions, Ctx};
use crate::parse;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List ledger entries, newest first (crypto-transaction-list/v1).
    #[command(visible_alias = "ls")]
    List(ListArgs),
}

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Account UUID (from `cbase accounts list`). Defaults to the account set
    /// with `cbase config set account <UUID>`.
    #[arg(long, value_name = "ID")]
    pub account: Option<String>,
    #[command(flatten)]
    pub range: RangeArgs,
}

pub fn run(ctx: &Ctx, cmd: &Cmd) -> Result<(), CliError> {
    let Cmd::List(args) = cmd;
    // Everything that can fail on the user's input fails here, before the
    // keychain is opened or a request is signed.
    args.range.validate()?;
    let account = ctx.account(args.account.as_deref())?;

    let path = account_transactions(&account);
    let rows = ctx
        .client()?
        .get_all(&path, &[], fetch_limit(&args.range))?;

    let parsed = parse::transactions(&rows);
    let mut txns = parse::within(
        parsed,
        args.range.since.as_deref(),
        args.range.until.as_deref(),
        |t| t.date.as_str(),
    );
    if let Some(n) = args.range.limit {
        txns.truncate(n as usize);
    }

    Paged::new("crypto-transaction", txns).emit(ctx.common.json);
    Ok(())
}

/// How many records to pull before filtering.
///
/// With no date bounds, `--limit N` is exactly N records off the front of a
/// newest-first list, so it can be pushed down to the fetch. With bounds, it
/// cannot: the wanted records may be anywhere in the history, and stopping at
/// N would silently return a prefix of the wrong range.
fn fetch_limit(range: &RangeArgs) -> Option<u32> {
    if range.since.is_none() && range.until.is_none() {
        range.limit
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(limit: Option<u32>, since: Option<&str>, until: Option<&str>) -> RangeArgs {
        RangeArgs {
            limit,
            since: since.map(String::from),
            until: until.map(String::from),
        }
    }

    #[test]
    fn a_bare_limit_is_pushed_down_to_the_fetch() {
        assert_eq!(fetch_limit(&range(Some(10), None, None)), Some(10));
        assert_eq!(fetch_limit(&range(None, None, None)), None);
    }

    /// The trap this guards: `--since 2025-01-01 --limit 10` must not fetch
    /// only the 10 newest records and then filter them down to two.
    #[test]
    fn a_dated_query_must_not_stop_paging_at_the_limit() {
        assert_eq!(
            fetch_limit(&range(Some(10), Some("2025-01-01"), None)),
            None
        );
        assert_eq!(
            fetch_limit(&range(Some(10), None, Some("2025-12-31"))),
            None
        );
    }
}
