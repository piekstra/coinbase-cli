//! `cbase` — piekstra-family CLI for Coinbase (`api.coinbase.com`).
//!
//! Conforms to piekstra-cli/1. Read-only: every command observes, none mutate.
//! The read-only guarantee is enforced in code — [`cbase::client::Coinbase`]
//! exposes no verb but GET, and `cbase api` refuses anything else — not merely
//! asserted in the docs.

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::{AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs};
use pk_cli_http::ApiArgs;
use pk_cli_secrets::CredentialStore;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

use cbase::client::Coinbase;
use cbase::commands::{accounts, api, transactions, Ctx, ACCOUNTS};
use cbase::config::{self, Config, KEYCHAIN_ACCOUNT};
use cbase::credential::{self, Credential};

const BIN: &str = "cbase";
const REPO: &str = "piekstra/coinbase-cli";

/// Coinbase accounts and transaction history from the command line — balances,
/// the full ledger, and cost-basis raw material. Read-only. Unofficial.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// CDP API key management and status.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Non-secret settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Coinbase wallets and their balances.
    #[command(subcommand, visible_alias = "wallets")]
    Accounts(accounts::Cmd),
    /// One wallet's ledger: buys, sells, sends, receives, rewards.
    #[command(subcommand)]
    Transactions(transactions::Cmd),
    /// Raw Coinbase API passthrough (GET only — this CLI is read-only).
    Api(ApiArgs),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Store a CDP API key and prove it works.
    Login(KeyLoginArgs),
    /// Report credential state (auth-status/v1).
    Status(StatusArgs),
    /// Clear stored state; --forget also removes the API key.
    Logout(LogoutArgs),
    /// Raw keychain write for rotation / headless setup (no verification).
    SetCredential(SetCredentialArgs),
}

#[derive(clap::Args, Debug)]
struct KeyLoginArgs {
    #[command(flatten)]
    base: LoginArgs,
}

#[derive(clap::Args, Debug)]
struct StatusArgs {
    /// Prove the stored key against Coinbase with a live request, not just
    /// that a key is present. Exits 3 if Coinbase rejects it.
    #[arg(long)]
    verify: bool,
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key (base_url, account).
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        std::process::exit(output::fail(&e, cli.common.json));
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    let store = ConfigStore::new(BIN);
    // `CBASE_KEYCHAIN_SERVICE` exists for the test suite: pointing it at a
    // service that holds nothing keeps the suite hermetic once a real key is
    // stored on the machine — reading a *missing* keychain item needs no user
    // approval and exits 3, whereas the real service would open the user's
    // actual credential (and, from the ad-hoc-signed binary `cargo test`
    // builds, throw a macOS keychain prompt per rebuild). It renames which
    // entry is read; it never carries key material, so secrets still arrive
    // only via keychain/stdin/env.
    let creds = match std::env::var("CBASE_KEYCHAIN_SERVICE") {
        Ok(service) if !service.is_empty() => CredentialStore::new(service),
        _ => CredentialStore::for_binary(BIN),
    };
    let cfg: Config = store.load()?;
    let ctx = Ctx {
        common: &cli.common,
        cfg: &cfg,
        creds: &creds,
    };

    match &cli.command {
        Command::Auth(cmd) => auth(cli, cmd, &store, &creds, &cfg),
        Command::Config(cmd) => config_cmd(cli, cmd, &store),
        Command::Accounts(cmd) => accounts::run(&ctx, cmd),
        Command::Transactions(cmd) => transactions::run(&ctx, cmd),
        Command::Api(args) => api::run(&ctx, args),
        Command::SelfUpdate(args) => Updater {
            repo: REPO.into(),
            binary: BIN.into(),
            target: env!("BUILD_TARGET").into(),
            current: env!("CARGO_PKG_VERSION").into(),
        }
        .run(args, cli.common.json, cli.common.quiet),
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            Ok(())
        }
        Command::Info => {
            let info = CliInfo::new(
                BIN,
                env!("CARGO_PKG_VERSION"),
                &format!("https://github.com/{REPO}"),
                AuthInfo {
                    required: true,
                    // The family's `AuthMethod` enum has no `api-key` variant,
                    // so `auth status` reports the nearest thing (`password`).
                    // `info.auth.method` is a free string, and this is the
                    // value a driver should trust: the credential is a CDP API
                    // key, not a password, and the setup step differs.
                    method: "api-key".into(),
                    login_hint: Some(format!(
                        "{BIN} auth set-credential --stdin < cdp_api_key.json"
                    )),
                },
                &["accounts", "transactions", "api"],
            );
            output::json(&serde_json::to_value(&info).unwrap());
            Ok(())
        }
    }
}

fn auth(
    cli: &Cli,
    cmd: &AuthCmd,
    store: &ConfigStore,
    creds: &CredentialStore,
    cfg: &Config,
) -> Result<(), CliError> {
    match cmd {
        AuthCmd::Login(args) => login(cli, args, creds, cfg),
        AuthCmd::Status(args) => status(cli, args, creds, cfg),
        AuthCmd::Logout(args) => {
            // There is no session to clear — a CDP key is the whole credential
            // — so a bare `logout` has nothing to do. Say so rather than
            // reporting a success that did nothing.
            if args.forget {
                creds.delete(KEYCHAIN_ACCOUNT)?;
                store.clear()?;
                if !cli.common.quiet {
                    eprintln!("API key removed from the keychain and config cleared");
                }
            } else if !cli.common.quiet {
                eprintln!(
                    "nothing to clear: cbase holds no session, only the stored API key — \
                     use `cbase auth logout --forget` to remove it"
                );
            }
            Ok(())
        }
        AuthCmd::SetCredential(args) => {
            if creds.get(KEYCHAIN_ACCOUNT)?.is_some() && !args.overwrite {
                return Err(CliError::Usage(
                    "an API key is already stored; pass --overwrite to replace it".into(),
                ));
            }
            let secret = args.source.read(None)?;
            // Parse before storing: a malformed key that only fails on first
            // use is a much worse experience than one rejected at write time.
            let cred = Credential::parse(secret.expose())?;
            creds.set(KEYCHAIN_ACCOUNT, &secret)?;
            if !cli.common.quiet {
                eprintln!(
                    "CDP API key {} ({}) stored in the OS keychain ({})",
                    cred.masked_key_id(),
                    cred.signer().algorithm(),
                    creds.service()
                );
                warn_if_ed25519(&cred);
            }
            Ok(())
        }
    }
}

/// Ed25519 is the CDP portal's default and recommended key type — and Coinbase
/// separately documents that the Coinbase App API surface does not support it
/// ("your authentication attempts may fail"). A user who takes the portal's
/// recommendation therefore gets a key that stores fine and 401s on first use,
/// which is a miserable thing to debug. Say it at store time.
fn warn_if_ed25519(cred: &Credential) {
    if cred.signer().algorithm() == "EdDSA" {
        eprintln!(
            "warning: this is an Ed25519 key. Coinbase documents the Coinbase App API \
             (api.coinbase.com) as supporting ECDSA only, so requests may be rejected. \
             If reads fail with HTTP 401, create an ECDSA key instead — see docs/api.md."
        );
    }
}

/// Store a key and prove it against Coinbase.
///
/// The difference from `set-credential` is the verification round trip;
/// `--no-verify` collapses the two.
fn login(
    cli: &Cli,
    args: &KeyLoginArgs,
    creds: &CredentialStore,
    cfg: &Config,
) -> Result<(), CliError> {
    if creds.get(KEYCHAIN_ACCOUNT)?.is_some() && !args.base.overwrite {
        return Err(CliError::Usage(
            "an API key is already stored; pass --overwrite to replace it".into(),
        ));
    }
    let prompt = if args.base.non_interactive {
        None
    } else {
        Some("CDP API key JSON (or pipe the file with --stdin)")
    };
    let secret = args.base.source.read(prompt)?;
    let cred = Credential::parse(secret.expose())?;
    creds.set(KEYCHAIN_ACCOUNT, &secret)?;
    if !cli.common.quiet {
        // Before the verification round trip, so a 401 arrives with its most
        // likely explanation already on screen.
        warn_if_ed25519(&cred);
    }

    if !args.base.no_verify {
        // A stored key that Coinbase rejects is worse than no key at all, so
        // prove it now. It stays stored either way — the fix is usually the
        // key's permissions, not the key.
        verify(cfg, creds)?;
    }
    if !cli.common.quiet {
        eprintln!(
            "CDP API key {} ({}) stored in the OS keychain ({})",
            cred.masked_key_id(),
            cred.signer().algorithm(),
            creds.service()
        );
    }
    Ok(())
}

/// One cheap authenticated read, to prove the key works.
fn verify(cfg: &Config, creds: &CredentialStore) -> Result<(), CliError> {
    let client = Coinbase::new(cfg, creds, false)?;
    client.get(ACCOUNTS, &[("limit", "1".into())])?;
    Ok(())
}

fn status(
    cli: &Cli,
    args: &StatusArgs,
    creds: &CredentialStore,
    cfg: &Config,
) -> Result<(), CliError> {
    // SPEC v1 §1.2: `auth status` works logged out — which has to include the
    // case where the keychain itself is unreachable. Failing here would make
    // the one command a driver uses to decide "do I need to log in?" the
    // command that can't answer.
    let (stored, keychain_note) = credential::peek_stored_key(creds);
    let parsed = stored
        .as_ref()
        .and_then(|s| Credential::parse(s.expose()).ok());

    // A stored key is necessary but not sufficient — Coinbase can revoke it
    // server-side. Only --verify proves it, and only --verify costs a request.
    let (authenticated, note) = match (&parsed, args.verify) {
        (None, _) => (false, keychain_note),
        (Some(_), false) => (true, None),
        (Some(_), true) => match verify(cfg, creds) {
            Ok(()) => (true, Some("key verified against Coinbase".to_string())),
            Err(CliError::Auth(m)) => (false, Some(m)),
            // A network failure says nothing about the credential.
            Err(e) => return Err(e),
        },
    };

    let mut st = AuthStatus::new(true, authenticated, pk_cli_auth::AuthMethod::Password);
    st.username = parsed.as_ref().map(|c| c.masked_key_id());
    st.account = cfg.account();
    st.credential_in_keychain = Some(stored.is_some());
    if args.verify {
        st.session_valid = Some(authenticated);
    }
    st.emit(cli.common.json);

    if let Some(note) = note {
        if !cli.common.quiet {
            eprintln!("{note}");
        }
    }
    // The DTO already went to stdout; exit directly rather than returning an
    // error that would print a second JSON document after it.
    if args.verify && !authenticated {
        std::process::exit(CliError::Auth(String::new()).exit_code());
    }
    Ok(())
}

fn config_cmd(cli: &Cli, cmd: &ConfigCmd, store: &ConfigStore) -> Result<(), CliError> {
    match cmd {
        ConfigCmd::Path => {
            println!("{}", store.path()?.display());
            Ok(())
        }
        ConfigCmd::Show => {
            let cfg: Config = store.load()?;
            let v = serde_json::to_value(&cfg).unwrap_or_default();
            if cli.common.json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
        ConfigCmd::Set { key, value } => {
            let mut cfg: Config = store.load()?;
            match key.as_str() {
                "base_url" => cfg.base_url = Some(value.clone()),
                "account" => cfg.account = Some(value.clone()),
                other => return Err(unknown_key(other)),
            }
            store.save(&cfg)
        }
        ConfigCmd::Unset { key } => {
            let mut cfg: Config = store.load()?;
            match key.as_str() {
                "base_url" => cfg.base_url = None,
                "account" => cfg.account = None,
                other => return Err(unknown_key(other)),
            }
            store.save(&cfg)
        }
    }
}

fn unknown_key(key: &str) -> CliError {
    CliError::Usage(format!(
        "unknown config key `{key}` (known: {})",
        config::KNOWN_KEYS.join(", ")
    ))
}
