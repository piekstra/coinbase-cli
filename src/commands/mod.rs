//! Domain command modules. Each read emits a `schema`-tagged DTO in `--json`
//! mode and a shaped table/kv view in text mode.

pub mod accounts;
pub mod api;
pub mod transactions;

use pk_cli_core::{CliError, CommonArgs};
use pk_cli_http::BlockingTransport;
use pk_cli_secrets::CredentialStore;

use crate::client::Coinbase;
use crate::config::Config;

pub use crate::client::{account_transactions, ACCOUNTS};
// The output contract lives in the shared crate; re-exported so the command
// modules keep their short `use super::{items, table_view}`.
pub use pk_cli_core::output::{rows_of as items, table_view};

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
    pub fn client(&self) -> Result<Coinbase<BlockingTransport>, CliError> {
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
