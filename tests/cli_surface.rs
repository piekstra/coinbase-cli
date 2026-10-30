//! Offline black-box tests of the command surface. No network, no keychain,
//! no credential: every case here is `--help`, argument validation, or a
//! discovery command, so nothing prompts, hangs, or reaches Coinbase.
//!
//! The rule these enforce is SPEC v1's "validate before you touch the keychain
//! or the network" — each exit-code case below would be a hang or a live
//! request if that rule were broken.

use assert_cmd::Command;
use predicates::str::contains;

/// Every invocation points the keychain at a service that holds nothing
/// (`CBASE_KEYCHAIN_SERVICE`). Without this, the exit-3 cases stop being
/// hermetic the moment a real key lives on the machine: the ad-hoc-signed
/// binary `cargo test` builds would open the developer's actual credential —
/// one macOS approval prompt per rebuild — and then reach Coinbase for real.
/// Found the hard way during the first live-verification run (2026-08-13).
fn cbase() -> Command {
    let mut cmd = Command::cargo_bin("cbase").expect("binary builds");
    cmd.env("CBASE_KEYCHAIN_SERVICE", "piekstra.cbase.hermetic-tests");
    cmd
}

/// Every top-level command. The help tests iterate this, so a renamed or
/// dropped command trips a test.
const COMMANDS: &[&str] = &[
    "auth",
    "config",
    "accounts",
    "transactions",
    "api",
    "self-update",
    "completions",
    "info",
];

/// Command groups whose `list` must carry the `ls` alias (SPEC v1 §1.3).
const LIST_GROUPS: &[&str] = &["accounts", "transactions"];

#[test]
fn top_level_help_lists_every_command() {
    let out = cbase().arg("--help").assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for cmd in COMMANDS {
        assert!(text.contains(cmd), "--help is missing `{cmd}`");
    }
}

#[test]
fn every_command_help_renders() {
    // Rendering each subcommand's help forces clap's debug assertions over that
    // subtree, catching a flag that collides with a global like `-q`/`-v`.
    for cmd in COMMANDS {
        cbase().args([cmd, "--help"]).assert().success();
    }
}

#[test]
fn list_subcommands_all_have_the_ls_alias() {
    for group in LIST_GROUPS {
        cbase().args([group, "ls", "--help"]).assert().success();
    }
}

#[test]
fn every_auth_subcommand_in_the_spec_exists() {
    for sub in ["login", "status", "logout", "set-credential"] {
        cbase().args(["auth", sub, "--help"]).assert().success();
    }
}

#[test]
fn every_config_subcommand_in_the_spec_exists() {
    for sub in ["path", "show", "set", "unset"] {
        cbase().args(["config", sub, "--help"]).assert().success();
    }
}

#[test]
fn the_accounts_alias_renders() {
    cbase().args(["wallets", "--help"]).assert().success();
}

/// A flag that parses and then does nothing is worse than no flag. Wallets are
/// not dated records, so `accounts list` must not advertise a date range.
#[test]
fn accounts_list_offers_no_meaningless_date_flags() {
    let out = cbase()
        .args(["accounts", "list", "--help"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(!text.contains("--since"), "accounts has no date dimension");
    assert!(!text.contains("--until"), "accounts has no date dimension");
    assert!(text.contains("--limit"), "--limit is still the paging knob");
    assert!(text.contains("--all"));

    cbase()
        .args(["accounts", "list", "--since", "2026-01-01"])
        .assert()
        .code(2);
}

/// …but `transactions list`, where dates are meaningful, must offer them.
#[test]
fn transactions_list_offers_the_date_flags() {
    let out = cbase()
        .args(["transactions", "list", "--help"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&out.get_output().stdout);
    for flag in ["--since", "--until", "--limit", "--account"] {
        assert!(text.contains(flag), "transactions list is missing {flag}");
    }
}

#[test]
fn version_prints_the_crate_version() {
    cbase()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn unknown_command_is_a_usage_error() {
    cbase().arg("no-such-command").assert().code(2);
}

#[test]
fn info_reports_the_cli_contract() {
    let out = cbase().arg("info").assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("info emits JSON");
    assert_eq!(v["name"], "cbase");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["auth"]["required"], true);
    // Not "password": the credential is a CDP API key, and a driver bootstrapping
    // from `info` needs to know that the setup step is different.
    assert_eq!(v["auth"]["method"], "api-key");
    let caps = v["capabilities"].as_array().unwrap();
    for expected in ["accounts", "transactions", "api"] {
        assert!(
            caps.iter().any(|c| c == expected),
            "capabilities missing {expected}"
        );
    }
}

#[test]
fn completions_render_for_every_supported_shell() {
    for shell in ["bash", "zsh", "fish"] {
        cbase().args(["completions", shell]).assert().success();
    }
}

#[test]
fn auth_status_answers_without_a_credential() {
    // Logged-out `auth status` must succeed (SPEC v1 §1.2), not exit 3.
    let out = cbase()
        .args(["auth", "status", "--json"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("auth status emits JSON");
    assert_eq!(v["schema"], "auth-status/v1");
    assert_eq!(v["required"], true);
    assert!(v["authenticated"].is_boolean());
}

// ---- The read-only guarantee ---------------------------------------------

#[test]
fn api_refuses_every_write_verb() {
    // Exit 6 (confirmation required), not 2 — a caller can tell "this tool
    // won't do that" from "you typed it wrong". Casing is not a bypass.
    for verb in ["POST", "PUT", "DELETE", "post", "PaTcH"] {
        cbase()
            .args(["api", verb, "/v2/accounts"])
            .assert()
            .code(6)
            .stderr(contains("read-only"));
    }
}

#[test]
fn api_allows_get() {
    // GET gets past the guard and fails at the credential instead — exit 3,
    // which proves the refusal above is about the verb and not the path.
    cbase()
        .args(["api", "GET", "/v2/accounts"])
        .assert()
        .code(3);
}

#[test]
fn api_rejects_a_body_even_on_get() {
    cbase()
        .args(["api", "GET", "/v2/accounts", "--data", "{}"])
        .assert()
        .code(2)
        .stderr(contains("read-only"));
}

// ---- Argument validation happens before any network/keychain access -------

#[test]
fn an_api_path_without_a_leading_slash_is_a_usage_error() {
    cbase()
        .args(["api", "GET", "v2/accounts"])
        .assert()
        .code(2)
        .stderr(contains("must start with"));
}

#[test]
fn an_inverted_date_range_is_a_usage_error() {
    cbase()
        .args([
            "transactions",
            "list",
            "--account",
            "00000000-0000-0000-0000-000000000000",
            "--since",
            "2026-08-01",
            "--until",
            "2026-01-01",
        ])
        .assert()
        .code(2)
        .stderr(contains("is after"));
}

#[test]
fn a_non_iso_date_is_a_usage_error() {
    cbase()
        .args([
            "transactions",
            "list",
            "--account",
            "00000000-0000-0000-0000-000000000000",
            "--since",
            "08/01/2026",
        ])
        .assert()
        .code(2);
}

/// The date range is validated *before* the missing-account check, so a
/// malformed date is reported even when both are wrong. Ordering matters
/// because the account check is the one that would otherwise read config.
#[test]
fn transactions_without_an_account_is_a_usage_error() {
    cbase()
        .args(["transactions", "list"])
        .assert()
        .code(2)
        .stderr(contains("--account"));
}

#[test]
fn an_unknown_config_key_is_a_usage_error() {
    cbase()
        .args(["config", "set", "nonsense", "x"])
        .assert()
        .code(2)
        .stderr(contains("unknown config key"));
}

#[test]
fn config_path_resolves_without_a_credential() {
    cbase().args(["config", "path"]).assert().success();
}

// ---- The exit-code contract (SPEC v1 §1.5) --------------------------------

/// Exit 3, not 1, whether the keychain is empty *or* entirely unavailable.
///
/// The second case is what a headless Linux box (no D-Bus secret service) does,
/// i.e. CI — and `pk-cli-secrets` reports it as `CliError::Keychain`, which maps
/// to the generic exit 1. `credential::read_stored_key` deliberately re-maps it:
/// from the caller's side the request could not be authenticated either way, and
/// exit 3 is the code a driver can actually act on. Both messages name the
/// command that fixes it.
#[test]
fn a_read_without_a_credential_exits_three_with_the_fix_in_the_message() {
    let out = cbase()
        .args(["accounts", "list", "--json"])
        .assert()
        .code(3);
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("the error DTO is JSON");
    assert_eq!(v["error"]["code"], "auth");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("set-credential"),
        "an auth error must name the command that fixes it, got: {msg}"
    );
}

/// Exactly one JSON document per invocation (SPEC v1 §1.4) — an error path that
/// emits a DTO *and* an error would break every consumer that parses stdout.
#[test]
fn a_failing_json_invocation_emits_exactly_one_document() {
    let out = cbase()
        .args(["accounts", "list", "--json"])
        .assert()
        .code(3);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("stdout is one JSON document, not two concatenated");
}

/// Secrets must never be accepted on argv (SPEC v1 §1.7). If a `--key`,
/// `--secret`, or `--private-key` flag ever appears, this fails.
#[test]
fn no_command_accepts_a_secret_on_argv() {
    for cmd in [
        vec!["auth", "login", "--help"],
        vec!["auth", "set-credential", "--help"],
    ] {
        let out = cbase().args(&cmd).assert().success();
        let text = String::from_utf8_lossy(&out.get_output().stdout).to_lowercase();
        for banned in [
            "--key",
            "--secret",
            "--private-key",
            "--password",
            "--token",
        ] {
            assert!(
                !text.contains(banned),
                "{cmd:?} exposes `{banned}` — secrets must arrive via --stdin/--from-env only"
            );
        }
        // And the approved ingestion paths must be present.
        assert!(text.contains("--stdin"), "{cmd:?} is missing --stdin");
        assert!(text.contains("--from-env"), "{cmd:?} is missing --from-env");
    }
}
