//! Domain command modules. Each read emits a `schema`-tagged DTO in `--json`
//! mode and a shaped table/kv view in text mode.

pub mod accounts;
pub mod api;
pub mod transactions;

use pk_cli_core::{CliError, CommonArgs};
use pk_cli_secrets::CredentialStore;

use crate::client::Coinbase;
use crate::config::Config;

// The output contract lives in the shared crate; re-exported so the command
// modules keep their short `use super::{items, table_view}`.
pub use pk_cli_core::output::{rows_of as items, table_view};

/// Coinbase API paths the reads share.
pub const ACCOUNTS: &str = "/v2/accounts";

/// The transactions path for one account.
pub fn account_transactions(account_id: &str) -> String {
    format!("/v2/accounts/{account_id}/transactions")
}

pub struct Ctx<'a> {
    pub common: &'a CommonArgs,
    pub cfg: &'a Config,
    pub creds: &'a CredentialStore,
}

impl Ctx<'_> {
    /// A signing client built from the keychain key.
    ///
    /// There is no session to refresh and no re-auth ladder: a CDP key does
    /// not expire mid-run, so a 401 means the key is wrong or revoked and
    /// retrying it would only waste a round trip.
    pub fn client(&self) -> Result<Coinbase, CliError> {
        Coinbase::new(self.cfg, self.creds, self.common.verbose)
    }

    /// The account to act on: the flag, else the configured default.
    pub fn account(&self, flag: Option<&str>) -> Result<String, CliError> {
        flag.map(String::from)
            .or_else(|| self.cfg.account())
            .ok_or_else(|| {
                CliError::Usage(
                    "no account given — pass `--account <UUID>`, set a default with \
                     `cbase config set account <UUID>`, or run `cbase accounts list` to find one"
                        .into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_paths_are_scoped_to_the_account() {
        assert_eq!(
            account_transactions("abc-123"),
            "/v2/accounts/abc-123/transactions"
        );
    }
}
