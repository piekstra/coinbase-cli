//! Contract tests over the fixtures in `tests/fixtures/`.
//!
//! These run the real parsers against the response shapes Coinbase sends, so a
//! field rename fails loudly here instead of silently emptying a column.
//!
//! **These fixtures are scrubbed captures from the first live run
//! (2026-08-13, `CB-VERSION: 2022-01-06`)** — see `tests/fixtures/README.md`
//! for what was captured and how it was scrubbed. Structure (keys, nesting,
//! null-vs-absent, sign conventions) is real; every value is a dummy. The one
//! deliberate exception is `accounts_last_page.json`, which keeps the
//! documented legacy string-`currency` shape that the live account no longer
//! serves.

use cbase::client::next_cursor;
use cbase::parse;
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

fn rows(page: &Value) -> Vec<Value> {
    page.get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

// ---- accounts -------------------------------------------------------------

#[test]
fn accounts_parse_into_the_columns_the_table_renders() {
    let page = fixture("accounts.json");
    let accounts = parse::accounts(&rows(&page));
    assert_eq!(accounts.len(), 3, "every documented row must parse");

    let btc = &accounts[0];
    assert_eq!(btc.id, "20000000-0000-0000-0000-000000000001");
    assert_eq!(btc.name, "Sample BTC Wallet");
    // `currency` is an OBJECT here — the code must read `.code`, not the object.
    assert_eq!(btc.currency, "BTC");
    assert_eq!(btc.balance.amount, "1.23450000");
    assert_eq!(btc.balance.currency, "BTC");
    assert_eq!(btc.kind.as_deref(), Some("wallet"));
    assert_eq!(btc.primary, Some(true));
    assert!(btc.updated_at.is_some());
}

/// Coinbase documents `currency` as a bare string on older API versions. The
/// live capture (130 accounts) served only the object shape, but the legacy
/// shape is cheap to keep parsing and version-dependent to encounter.
#[test]
fn the_legacy_string_currency_shape_still_parses() {
    let page = fixture("accounts_last_page.json");
    let accounts = parse::accounts(&rows(&page));
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].currency, "BTC");
    assert_eq!(accounts[0].balance.amount, "0.00000001");
}

/// Eight decimal places must survive the round trip. A dust balance rounded to
/// zero is a wrong answer that looks like a right one.
#[test]
fn satoshi_precision_survives_parsing_and_serialization() {
    let page = fixture("accounts_last_page.json");
    let accounts = parse::accounts(&rows(&page));
    let json = serde_json::to_string(&accounts[0]).unwrap();
    assert!(
        json.contains("0.00000001"),
        "precision lost in the DTO: {json}"
    );
}

// ---- pagination -----------------------------------------------------------

/// The bug this pins: the documented pagination block has no
/// `next_starting_after`, only `next_uri`. Live captures show *both* on every
/// page — but `next_uri` is the published contract, so it stays primary, and
/// reading only the undocumented field risks a walk that stops after page one
/// and reports a partial ledger as a complete one. Note the captured
/// `next_uri` carries no `limit=` parameter — just `?starting_after=`.
#[test]
fn the_cursor_comes_out_of_next_uri() {
    let page = fixture("accounts.json");
    assert_eq!(
        next_cursor(&page).as_deref(),
        Some("20000000-0000-0000-0000-000000000003"),
        "the cursor must be parsed out of pagination.next_uri"
    );
}

#[test]
fn a_null_next_uri_ends_the_walk() {
    assert!(next_cursor(&fixture("accounts_last_page.json")).is_none());
    assert!(next_cursor(&fixture("transactions.json")).is_none());
}

// ---- transactions ---------------------------------------------------------

#[test]
fn transactions_parse_into_the_columns_the_table_renders() {
    let page = fixture("transactions.json");
    let txns = parse::transactions(&rows(&page));
    assert_eq!(txns.len(), 12, "every captured row must parse");

    let buy = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("buy"))
        .expect("the capture has a buy row");
    assert_eq!(buy.status.as_deref(), Some("completed"));
    assert_eq!(buy.amount.amount, "0.10000000");
    assert_eq!(buy.amount.currency, "BTC");
    let native = buy.native_amount.as_ref().expect("native_amount present");
    assert_eq!(native.amount, "1000.00");
    assert_eq!(native.currency, "USD");
    // Live reality: most rows carry no `description` and no `details` at all.
    // A buy has neither; the DTO must omit the field, not invent a label.
    assert!(buy.description.is_none());
    assert_eq!(buy.date, "2026-03-26");
}

/// Pins the live capture's negative space: `details` and `updated_at` were on
/// no row of a 3,559-entry ledger (`CB-VERSION: 2022-01-06`), even though both
/// are documented. This stops the fixtures drifting back toward invented
/// shapes the parsers would then silently depend on.
#[test]
fn captured_rows_carry_no_details_or_updated_at() {
    for row in rows(&fixture("transactions.json")) {
        assert!(row.get("details").is_none(), "details never appears live");
        assert!(
            row.get("updated_at").is_none(),
            "updated_at never appears live"
        );
    }
}

/// Both amounts must survive: the asset quantity and Coinbase's fiat
/// valuation. Neither is recoverable from the other, and 8949 needs both.
#[test]
fn both_the_asset_and_the_fiat_amount_are_kept() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    for t in &txns {
        assert!(!t.amount.amount.is_empty(), "{} lost its amount", t.id);
        assert!(t.native_amount.is_some(), "{} lost its native_amount", t.id);
    }
}

/// Debits stay negative. A parser that dropped the sign would turn a disposal
/// into an acquisition.
#[test]
fn outgoing_amounts_keep_their_negative_sign() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    let send = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("send"))
        .unwrap();
    assert!(
        send.amount.amount.starts_with('-'),
        "a send must be negative, got {}",
        send.amount.amount
    );
    assert!(send.native_amount.as_ref().unwrap().amount.starts_with('-'));
}

/// The commission lives only inside `advanced_trade_fill`. A basis figure
/// computed without it is wrong.
#[test]
fn an_advanced_trade_fill_keeps_its_commission_and_price() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    let fill_txn = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("advanced_trade_fill"))
        .expect("the fixture has an advanced_trade_fill row");
    let fill = fill_txn.fill.as_ref().expect("fill detail parsed");
    assert_eq!(fill.commission.as_deref(), Some("2.50"));
    assert_eq!(fill.fill_price.as_deref(), Some("50000.00"));
    assert_eq!(fill.product_id.as_deref(), Some("BTC-USD"));
    assert_eq!(fill.side.as_deref(), Some("BUY"));
}

/// Reward income arrives under (at least) FOUR spellings, and the most common
/// one is not in Coinbase's documentation at all.
///
/// The docs list no `staking_reward` and imply `earn_payout` is the staking
/// spelling; this repo's first draft even pinned "`staking_reward` does not
/// exist" as a test. The first live capture (2026-08-13) refuted it: a real
/// ledger held 1,410 `staking_reward` rows against 20 `earn_payout`, plus
/// `inflation_reward` and `interest`. Any income filter must match all four —
/// matching one spelling silently underreports income, a wrong tax answer
/// that looks like a right one.
#[test]
fn reward_income_arrives_under_four_spellings() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    for kind in [
        "staking_reward",
        "earn_payout",
        "inflation_reward",
        "interest",
    ] {
        assert!(
            txns.iter().any(|t| t.kind.as_deref() == Some(kind)),
            "the capture must keep a `{kind}` row — all four income spellings are live"
        );
    }
}

/// Inbound transfers arrive as **positive `send`** rows (the live capture had
/// 473 of them, many with a `from` block) — the documented `receive` type
/// never appeared. Dropping the sign, or treating `send` as always-outgoing,
/// misclassifies received assets.
#[test]
fn inbound_transfers_are_positive_sends() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    assert!(
        txns.iter()
            .any(|t| t.kind.as_deref() == Some("send") && !t.amount.amount.starts_with('-')),
        "the capture must keep an inbound (positive) send"
    );
}

/// A simple buy/sell itemizes its fee inside the `buy`/`sell` block — kept in
/// the DTO as `trade_fee` because, like the fill commission, nothing at the
/// top level carries it and a fee-blind basis is wrong.
#[test]
fn a_buy_or_sell_keeps_its_itemized_fee() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    let buy = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("buy"))
        .unwrap();
    assert_eq!(
        buy.trade_fee.as_ref().map(|f| f.amount.as_str()),
        Some("14.90")
    );
    let sell = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("sell"))
        .unwrap();
    assert_eq!(
        sell.trade_fee.as_ref().map(|f| f.amount.as_str()),
        Some("7.45")
    );
}

#[test]
fn a_send_keeps_its_network_fee() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    let send = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("send"))
        .unwrap();
    let fee = send.network_fee.as_ref().expect("network fee parsed");
    assert_eq!(fee.amount, "0.00001000");
    assert_eq!(fee.currency, "BTC");
}

/// Rows without a fill or a network block must omit those keys rather than
/// emit nulls (SPEC v1 §1.4).
#[test]
fn absent_optional_blocks_are_omitted_not_nulled() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    let reward = txns
        .iter()
        .find(|t| t.kind.as_deref() == Some("staking_reward"))
        .unwrap();
    let v = serde_json::to_value(reward).unwrap();
    assert!(v.get("fill").is_none(), "fill must be omitted on a reward");
    assert!(v.get("network_fee").is_none());
    assert!(v.get("trade_fee").is_none());
    assert!(v.get("description").is_none());
}

// ---- date filtering -------------------------------------------------------

/// `--since`/`--until` are applied client-side because the endpoint has no date
/// parameters. This pins that the filter actually bounds the fixture.
#[test]
fn client_side_date_filtering_bounds_the_ledger() {
    let txns = parse::transactions(&rows(&fixture("transactions.json")));
    let total = txns.len();
    let in_2026 = parse::within(txns.clone(), Some("2026-01-01"), Some("2026-12-31"), |t| {
        t.date.as_str()
    });
    assert!(
        in_2026.len() < total,
        "the filter must exclude the 2025 rows"
    );
    assert!(in_2026.iter().all(|t| t.date.starts_with("2026")));

    let none = parse::within(txns, Some("2030-01-01"), None, |t| t.date.as_str());
    assert!(none.is_empty());
}

// ---- errors ---------------------------------------------------------------

#[test]
fn the_v2_error_body_shape_is_what_the_client_expects() {
    let body = fixture("error_v2.json");
    let first = body["errors"][0].clone();
    assert!(first.get("id").is_some(), "v2 errors carry an `id`");
    assert!(
        first.get("message").is_some(),
        "v2 errors carry a `message`"
    );
}

// ---- the scrubbing rule ---------------------------------------------------

/// Stated positively: every identity-bearing value in a fixture must match a
/// known dummy shape. Written this way on purpose — a denylist of real names
/// would publish exactly what it exists to keep out.
///
/// Extend this whenever a new kind of identifier enters a fixture.
#[test]
fn fixtures_carry_only_dummy_identifiers() {
    for name in [
        "accounts.json",
        "accounts_last_page.json",
        "transactions.json",
        "error_v2.json",
    ] {
        let raw = std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        check_dummy(&v, name);

        // No credential-shaped material, ever. A fixture is the easiest place
        // for a real token to hide.
        for banned in [
            "BEGIN ",
            "PRIVATE KEY",
            "Bearer ",
            "eyJ", // a JWT's base64url header
            "organizations/",
            "@gmail",
            "@icloud",
        ] {
            assert!(
                !raw.contains(banned),
                "{name} contains `{banned}` — fixtures must never hold credential material"
            );
        }
    }
}

/// Every UUID-shaped string must be one of the deliberately fake ones: all
/// segments zero except a short numeric tail. On-chain `address` values (an
/// identifier kind the live capture introduced) must be obvious dummies too.
fn check_dummy(v: &Value, file: &str) {
    match v {
        Value::String(s) => {
            if looks_like_uuid(s) {
                assert!(
                    is_dummy_uuid(s),
                    "{file} has a UUID that is not an obvious dummy: {s}"
                );
            }
        }
        Value::Array(a) => a.iter().for_each(|x| check_dummy(x, file)),
        Value::Object(o) => o.iter().for_each(|(k, x)| {
            if k == "address" {
                if let Some(s) = x.as_str() {
                    assert!(
                        is_dummy_address(s),
                        "{file} has an address that is not an obvious dummy: {s}"
                    );
                }
            }
            check_dummy(x, file);
        }),
        _ => {}
    }
}

/// A dummy on-chain address says so: it contains the literal `dummy` or is
/// all zeros after its prefix. A real address has entropy everywhere.
fn is_dummy_address(s: &str) -> bool {
    s.contains("dummy") || s.chars().filter(|c| *c != '0').count() <= 4
}

fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// A dummy UUID is one whose characters are all `0`, `-`, or a single-digit
/// tail — i.e. `20000000-0000-0000-0000-000000000001`. Anything with real
/// entropy fails.
fn is_dummy_uuid(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| *c != '-').collect();
    let nonzero = digits.chars().filter(|c| *c != '0').count();
    nonzero <= 3
        && digits
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_hexdigit())
}

#[cfg(test)]
mod meta {
    use super::*;

    /// The scrub check has to be able to fail, or it proves nothing.
    #[test]
    fn the_dummy_uuid_rule_rejects_a_real_looking_uuid() {
        assert!(is_dummy_uuid("20000000-0000-0000-0000-000000000001"));
        assert!(is_dummy_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(!is_dummy_uuid("58542935-67b5-56e1-a3f9-42686e07fa40"));
        assert!(!is_dummy_uuid("8bfc20d7-f7c6-4422-bf07-8243ca4169fe"));
        assert!(looks_like_uuid("58542935-67b5-56e1-a3f9-42686e07fa40"));
        assert!(!looks_like_uuid("not-a-uuid"));
    }

    /// Same for the address rule: it must reject a plausibly real address.
    #[test]
    fn the_dummy_address_rule_rejects_a_real_looking_address() {
        assert!(is_dummy_address("bc1qdummy000000000000000000000000000000"));
        assert!(!is_dummy_address(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));
    }
}
