//! The `cbase mcp` tools, offline: every tool runs in process against the
//! scrubbed fixtures through the `Source` seam, and cli-common's conformance
//! helper checks the definitions and every result's shape and size.

use std::sync::Mutex;

use cbase::mcp::{CoinbaseTools, Source, ACCOUNTS_TOOL, TRANSACTIONS_TOOL};
use pk_cli_core::CliError;
use pk_cli_mcp::conformance::{assert_conforms, assert_fits, call, definition_size};
use pk_cli_mcp::CallToolResult;
use serde_json::{json, Value};

fn fixture_rows(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let page: Value = serde_json::from_str(&raw).unwrap();
    page["data"].as_array().cloned().unwrap_or_default()
}

/// Both account pages, as `get_all` would return them, and one ledger for
/// any account id.
struct Fixtures {
    accounts: Vec<Value>,
    transactions: Vec<Value>,
    /// The `limit` of every transactions fetch, to check the pushdown.
    fetches: Mutex<Vec<Option<u32>>>,
    /// When set, every call fails with this.
    fail: Mutex<Option<CliError>>,
}

impl Fixtures {
    fn new() -> Self {
        let mut accounts = fixture_rows("accounts.json");
        accounts.extend(fixture_rows("accounts_last_page.json"));
        Self {
            accounts,
            transactions: fixture_rows("transactions.json"),
            fetches: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    fn with_transactions(mut self, rows: Vec<Value>) -> Self {
        self.transactions = rows;
        self
    }

    fn fetches(&self) -> Vec<Option<u32>> {
        self.fetches.lock().unwrap().clone()
    }

    fn failure(&self) -> Option<CliError> {
        self.fail.lock().unwrap().clone()
    }
}

impl Source for Fixtures {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        match self.failure() {
            Some(e) => Err(e),
            None => Ok(self.accounts.clone()),
        }
    }

    async fn transactions(
        &self,
        _account_id: &str,
        limit: Option<u32>,
    ) -> Result<Vec<Value>, CliError> {
        self.fetches.lock().unwrap().push(limit);
        if let Some(e) = self.failure() {
            return Err(e);
        }
        let n = limit.map_or(usize::MAX, |l| l as usize);
        Ok(self.transactions.iter().take(n).cloned().collect())
    }
}

fn tools() -> CoinbaseTools<Fixtures> {
    CoinbaseTools::new(Fixtures::new(), None)
}

fn ok<'r>(tools: &CoinbaseTools<Fixtures>, name: &str, r: &'r CallToolResult) -> &'r Value {
    assert_fits(tools, name, r)
}

fn err(r: &CallToolResult) -> &str {
    assert!(r.is_error(), "expected an error, got {}", r.text());
    assert!(r.structured().is_none());
    r.text()
}

fn names(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i[key].as_str().unwrap().to_string())
        .collect()
}

// ---- the definitions --------------------------------------------------------

#[test]
fn the_tools_conform_to_the_mcp_profile() {
    assert_conforms(&tools());
}

#[test]
fn the_tools_are_reads_and_stay_small() {
    let t = tools();
    let list = pk_cli_mcp::tools_list_json(&t);
    for tool in list["tools"].as_array().unwrap() {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
        assert!(tool.get("_meta").is_none(), "no write markers on a read");
    }
    assert!(definition_size(&t, ACCOUNTS_TOOL) < 2_500);
    assert!(definition_size(&t, TRANSACTIONS_TOOL) < 3_500);
}

// ---- coinbase_accounts -------------------------------------------------------

#[test]
fn accounts_concise_leaves_out_empty_wallets_and_ids() {
    let t = tools();
    let r = call(&t, ACCOUNTS_TOOL, json!({}));
    let page = ok(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(page["returned"], 3);
    assert_eq!(
        names(&page["items"], "name"),
        [
            "Sample BTC Wallet",
            "Sample USD Wallet",
            "Sample Legacy Wallet"
        ]
    );
    let btc = &page["items"][0];
    assert_eq!(btc["balance"], "1.23450000", "full precision, as written");
    assert_eq!(btc["currency"], "BTC");
    assert!(btc.get("id").is_none() && btc.get("updated_at").is_none());
    assert!(page.get("next_cursor").is_none());
}

#[test]
fn accounts_detailed_with_zero_adds_ids_and_every_wallet() {
    let t = tools();
    let r = call(
        &t,
        ACCOUNTS_TOOL,
        json!({"include_zero": true, "response_format": "detailed"}),
    );
    let page = ok(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(page["returned"], 4);
    let eth = &page["items"][2];
    assert_eq!(eth["name"], "Sample Staked ETH");
    assert_eq!(eth["balance"], "0.00000000");
    assert!(
        eth["id"].as_str().unwrap().starts_with("20000000-"),
        "{eth}"
    );
}

#[test]
fn accounts_narrow_by_currency_case_blind() {
    let t = tools();
    let r = call(&t, ACCOUNTS_TOOL, json!({"currency": "btc"}));
    let page = ok(&t, ACCOUNTS_TOOL, &r);
    assert_eq!(
        names(&page["items"], "name"),
        ["Sample BTC Wallet", "Sample Legacy Wallet"]
    );
}

#[test]
fn accounts_page_with_a_cursor() {
    let t = tools();
    let first = call(&t, ACCOUNTS_TOOL, json!({"limit": 2}));
    let first = ok(&t, ACCOUNTS_TOOL, &first);
    assert_eq!(first["returned"], 2);
    let cursor = first["next_cursor"].as_str().unwrap();
    let second = call(&t, ACCOUNTS_TOOL, json!({"limit": 2, "cursor": cursor}));
    let second = ok(&t, ACCOUNTS_TOOL, &second);
    assert_eq!(names(&second["items"], "name"), ["Sample Legacy Wallet"]);
    assert!(second.get("next_cursor").is_none());

    let replay = call(
        &t,
        ACCOUNTS_TOOL,
        json!({"limit": 2, "cursor": cursor, "include_zero": true}),
    );
    assert!(err(&replay).contains("different filters"));
}

// ---- coinbase_transactions ---------------------------------------------------

#[test]
fn transactions_concise_by_wallet_name() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Sample BTC Wallet"}),
    );
    let out = ok(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(
        out["account"],
        json!({"name": "Sample BTC Wallet", "currency": "BTC"})
    );
    assert_eq!(out["returned"], 12);
    let items = out["items"].as_array().unwrap();
    let first = &items[0];
    assert_eq!(first["date"], "2026-08-10");
    assert_eq!(first["type"], "staking_reward");
    assert_eq!(first["amount"], "0.00013400");
    assert_eq!(first["native_currency"], "USD");
    assert!(first.get("id").is_none(), "concise: no ids");
    assert!(
        first.get("status").is_none(),
        "concise: completed is implied"
    );
    // An empty memo is dropped; a real one is kept, as data.
    assert!(items[3].get("description").is_none(), "{}", items[3]);
    assert_eq!(items[10]["description"], "Sample memo");
    // No filters: the fetch asks Coinbase for no more than the page needs.
    assert_eq!(t_source(&t).fetches(), [Some(26)]);
}

#[test]
fn transactions_detailed_adds_ids_fees_and_fills() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Sample BTC Wallet", "response_format": "detailed", "types": ["advanced_trade_fill"]}),
    );
    let out = ok(&t, TRANSACTIONS_TOOL, &r);
    assert!(out["account"]["id"].is_string());
    let fill = &out["items"][0];
    assert!(fill["id"].is_string(), "{fill}");
    assert_eq!(fill["status"], "completed");
    assert!(fill["fill"].is_object(), "{fill}");
}

#[test]
fn rewards_stands_for_all_four_reward_types() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Sample BTC Wallet", "types": ["rewards"]}),
    );
    let out = ok(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(
        names(&out["items"], "type"),
        [
            "staking_reward",
            "interest",
            "inflation_reward",
            "earn_payout"
        ]
    );
    // A filter can match anywhere in the ledger: the whole of it is read.
    assert_eq!(t_source(&t).fetches(), [None]);
}

#[test]
fn transactions_narrow_by_dates_inclusive() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Sample BTC Wallet", "since": "2026-01-20", "until": "2026-05-10"}),
    );
    let out = ok(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(
        names(&out["items"], "date"),
        ["2026-05-10", "2026-03-26", "2026-02-15", "2026-01-20"]
    );
}

#[test]
fn transactions_walk_the_ledger_page_by_page() {
    let t = tools();
    let mut cursor: Option<String> = None;
    let mut seen = Vec::new();
    loop {
        let mut args = json!({"account": "Sample BTC Wallet", "limit": 5});
        if let Some(c) = &cursor {
            args["cursor"] = json!(c);
        }
        let r = call(&t, TRANSACTIONS_TOOL, args);
        let out = ok(&t, TRANSACTIONS_TOOL, &r).clone();
        seen.extend(names(&out["items"], "date"));
        match out["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 12);
    assert_eq!(t_source(&t).fetches(), [Some(6), Some(11), Some(16)]);
}

#[test]
fn the_configured_account_is_the_default() {
    let t = CoinbaseTools::new(Fixtures::new(), Some("Sample USD Wallet".into()));
    let r = call(&t, TRANSACTIONS_TOOL, json!({"limit": 1}));
    let out = assert_fits(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["account"]["name"], "Sample USD Wallet");
}

#[test]
fn a_currency_code_finds_its_only_wallet() {
    let t = tools();
    let r = call(&t, TRANSACTIONS_TOOL, json!({"account": "usd", "limit": 1}));
    assert_eq!(
        ok(&t, TRANSACTIONS_TOOL, &r)["account"]["name"],
        "Sample USD Wallet"
    );
}

#[test]
fn a_page_of_long_memos_stops_under_the_budget_and_says_how_to_narrow() {
    let template = fixture_rows("transactions.json")[10].clone();
    let rows: Vec<Value> = (0..200)
        .map(|i| {
            let mut row = template.clone();
            row["id"] = json!(format!("30000000-0000-0000-0000-{i:012}"));
            row["description"] = json!(format!("Sample memo {i} {}", "x".repeat(400)));
            row
        })
        .collect();
    let t = CoinbaseTools::new(Fixtures::new().with_transactions(rows), None);
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Sample BTC Wallet", "limit": 200}),
    );
    let out = ok(&t, TRANSACTIONS_TOOL, &r);
    assert_eq!(out["truncated"], true);
    let returned = out["returned"].as_u64().unwrap();
    assert!((10..200).contains(&returned), "{returned}");
    let hint = out["hint"].as_str().unwrap();
    assert!(
        hint.contains("since/until or types") && hint.contains("next_cursor"),
        "{hint}"
    );
    assert!(r.text().chars().count() <= pk_cli_mcp::shape::SIZE_BUDGET);
}

/// The size a model pays for one ordinary call: a concise page of the
/// fixture ledger.
#[test]
fn a_concise_page_is_small() {
    let t = tools();
    let r = call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Sample BTC Wallet"}),
    );
    let size = r.text().chars().count();
    eprintln!("concise coinbase_transactions page of 12: {size} characters");
    assert!(size < 4_000, "{size}");
    let r = call(&t, ACCOUNTS_TOOL, json!({}));
    eprintln!(
        "concise coinbase_accounts page of 3: {} characters",
        r.text().chars().count()
    );
}

// ---- errors: actionable, and before any request -------------------------------

#[test]
fn an_ambiguous_currency_names_the_wallets_and_the_fix() {
    let t = tools();
    let text = err(&call(&t, TRANSACTIONS_TOOL, json!({"account": "BTC"}))).to_string();
    assert!(text.starts_with("not_found:"), "{text}");
    assert!(
        text.contains("Sample BTC Wallet") && text.contains("Sample Legacy Wallet"),
        "{text}"
    );
    assert!(text.contains("Call coinbase_accounts"), "{text}");
}

#[test]
fn an_unknown_wallet_is_not_found_with_the_fix() {
    let t = tools();
    let text = err(&call(
        &t,
        TRANSACTIONS_TOOL,
        json!({"account": "Nope Wallet"}),
    ))
    .to_string();
    assert!(text.starts_with("not_found:"), "{text}");
    assert!(text.contains("include_zero=true"), "{text}");
    assert!(t_source(&t).fetches().is_empty(), "no ledger fetched");
}

#[test]
fn bad_arguments_fail_before_any_request() {
    let t = tools();
    for (args, needle) in [
        (json!({}), "no account given"),
        (
            json!({"account": "Sample BTC Wallet", "since": "03/01/2026"}),
            "since must be a date",
        ),
        (
            json!({"account": "Sample BTC Wallet", "since": "2026-03-01", "until": "2026-02-01"}),
            "is after until",
        ),
        (
            json!({"account": "Sample BTC Wallet", "limit": 0}),
            "limit must be between",
        ),
        (
            json!({"account": "Sample BTC Wallet", "acount": "x"}),
            "unknown argument `acount`",
        ),
        (
            json!({"account": "Sample BTC Wallet", "cursor": "page-2"}),
            "next_cursor exactly",
        ),
    ] {
        let text = err(&call(&t, TRANSACTIONS_TOOL, args.clone())).to_string();
        assert!(text.starts_with("usage:"), "{args}: {text}");
        assert!(text.contains(needle), "{args}: {text}");
    }
    assert!(t_source(&t).fetches().is_empty());
}

#[test]
fn a_missing_key_tells_the_model_to_have_the_user_sign_in_in_a_terminal() {
    let t = tools();
    *t_source(&t).fail.lock().unwrap() = Some(cbase::client::missing_key());
    let text = err(&call(&t, ACCOUNTS_TOOL, json!({}))).to_string();
    assert!(text.starts_with("auth:"), "{text}");
    assert!(
        text.contains("cbase auth login") && text.contains("in a terminal"),
        "{text}"
    );
    assert!(text.contains("CBASE_API_KEY_NAME"), "{text}");
}

#[test]
fn an_upstream_failure_says_the_arguments_are_fine() {
    let t = tools();
    *t_source(&t).fail.lock().unwrap() = Some(CliError::Upstream("Coinbase answered 503".into()));
    let text = err(&call(&t, ACCOUNTS_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(text.contains("arguments are not the problem"), "{text}");
}

fn t_source(t: &CoinbaseTools<Fixtures>) -> &Fixtures {
    t.source()
}
