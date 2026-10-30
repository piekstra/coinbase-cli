//! Coinbase JSON → the DTOs this CLI emits.
//!
//! Every parser is total: a missing or wrongly-typed field yields `None` or a
//! placeholder, never a panic. Coinbase's v2 responses vary by `CB-VERSION`
//! and by account age (the `currency` field is an object on current versions
//! and a bare string on older ones), so tolerance here is not defensive
//! programming for its own sake — both shapes are live.
//!
//! **Amount strings are passed through verbatim.** A BTC balance carries eight
//! decimal places and a cost-basis calculation is only as good as the digits it
//! starts from, so nothing here rounds, reformats, or parses an amount into a
//! float. `Money.amount` is whatever Coinbase wrote.

use pk_cli_core::Money;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One Coinbase wallet (`crypto-account/v1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAccount {
    /// Account UUID — the `--account` value for `transactions list`.
    pub id: String,
    pub name: String,
    /// Asset code: `BTC`, `ETH`, `USD`, …
    pub currency: String,
    /// Balance in the account's own asset, at the provider's precision.
    pub balance: Money,
    /// `wallet` | `fiat` | `vault` | …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Whether this is the primary account for its currency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    /// RFC 3339, as Coinbase sent it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// One ledger entry (`crypto-transaction/v1`) — the raw material for cost basis
/// and Form 8949.
///
/// Both amounts are kept: `amount` is the asset quantity that moved (signed —
/// negative leaves the account) and `native_amount` is Coinbase's own fiat
/// valuation at the time. Neither is derivable from the other after the fact,
/// so dropping either would make the record useless for basis work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoTransaction {
    pub id: String,
    /// ISO `YYYY-MM-DD` (UTC), for filtering and tax-year bucketing.
    pub date: String,
    /// Coinbase's transaction type, passed through as sent.
    ///
    /// The documented set is long, changes over time, and — verified live
    /// 2026-08-13 — is **incomplete**: a real ledger walk surfaced nine types
    /// the docs don't list (`staking_reward`, `interest`, `inflation_reward`,
    /// `pro_deposit`, `pro_withdrawal`, `exchange_deposit`,
    /// `exchange_withdrawal`, `asset_migration`, `retail_eth2_deprecation`).
    /// So nothing here validates against a list — an unrecognized type must
    /// still appear in the output, because an entry this tool silently dropped
    /// is an entry missing from a tax return.
    ///
    /// Worth knowing for income filtering: staking/reward income arrives under
    /// **at least four spellings** — `staking_reward` (the most common, despite
    /// being undocumented), `earn_payout`, `inflation_reward`, and `interest`.
    /// `staking_transfer`/`unstaking_transfer` are principal movements, not
    /// income. Filtering for one spelling silently underreports income.
    /// Advanced Trade executions arrive as `advanced_trade_fill`, and inbound
    /// transfers arrive as **positive `send`** rows (there is no `receive` in
    /// practice).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// `completed` | `pending` | `failed` | `canceled` | `expired` |
    /// `waiting_for_clearing` | `waiting_for_signature`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Asset quantity moved, signed.
    pub amount: Money,
    /// Coinbase's fiat valuation of that quantity, signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_amount: Option<Money>,
    /// Coinbase's own one-line label ("Bought Bitcoin", "Sent Ethereum").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Execution detail, on `advanced_trade_fill` entries only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill: Option<FillDetail>,
    /// The on-chain fee Coinbase charged, on sends only
    /// (`network.transaction_fee`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_fee: Option<Money>,
    /// The fee inside a `buy` or `sell` block, when Coinbase itemizes one
    /// (`buy.fee` / `sell.fee`). Observed live 2026-08-13; like the fill
    /// commission, no top-level field carries it, and a cost basis that
    /// ignores it is wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trade_fee: Option<Money>,
    /// The full RFC 3339 timestamp, preserved because `date` alone loses the
    /// time of day — and intra-day ordering decides lot matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Advanced Trade execution detail (`transaction.advanced_trade_fill`).
///
/// Carried because the top-level `amount`/`native_amount` pair does not include
/// the **commission**, and a Form 8949 cost basis that omits fees is wrong.
/// Coinbase documents the commission as always denominated in the quote
/// currency of `product_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillDetail {
    /// e.g. `BTC-USD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    /// `BUY` | `SELL`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    /// Execution price, in the quote currency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_price: Option<String>,
    /// Fee charged, in the quote currency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
}

/// Parse `GET /v2/accounts` rows.
pub fn accounts(rows: &[Value]) -> Vec<CryptoAccount> {
    rows.iter().filter_map(account).collect()
}

fn account(row: &Value) -> Option<CryptoAccount> {
    let id = str_at(row, "id")?.to_string();
    let currency = currency_code(row.get("currency"))
        .or_else(|| {
            row.get("balance")
                .and_then(|b| str_at(b, "currency"))
                .map(String::from)
        })
        .unwrap_or_default();
    Some(CryptoAccount {
        id,
        name: str_at(row, "name").unwrap_or("").to_string(),
        currency: currency.clone(),
        balance: money_at(row, "balance").unwrap_or(Money {
            amount: "0".into(),
            currency,
        }),
        kind: str_at(row, "type").map(String::from),
        primary: row.get("primary").and_then(Value::as_bool),
        updated_at: str_at(row, "updated_at").map(String::from),
    })
}

/// Parse `GET /v2/accounts/:id/transactions` rows.
pub fn transactions(rows: &[Value]) -> Vec<CryptoTransaction> {
    rows.iter().filter_map(transaction).collect()
}

fn transaction(row: &Value) -> Option<CryptoTransaction> {
    let id = str_at(row, "id")?.to_string();
    let created = str_at(row, "created_at").map(String::from);
    Some(CryptoTransaction {
        id,
        date: created.as_deref().and_then(iso_date).unwrap_or_default(),
        kind: str_at(row, "type").map(String::from),
        status: str_at(row, "status").map(String::from),
        amount: money_at(row, "amount").unwrap_or(Money {
            amount: "0".into(),
            currency: String::new(),
        }),
        native_amount: money_at(row, "native_amount"),
        description: description(row),
        fill: fill_detail(row),
        network_fee: row
            .get("network")
            .and_then(|n| money_at(n, "transaction_fee")),
        trade_fee: trade_fee(row),
        created_at: created,
    })
}

/// The itemized fee inside a `buy` or `sell` block, when Coinbase includes one
/// (observed live 2026-08-13; absent, not null, otherwise). A row carries at
/// most one of the two blocks, so the order here is a formality.
fn trade_fee(row: &Value) -> Option<Money> {
    ["buy", "sell"]
        .iter()
        .find_map(|k| row.get(k).and_then(|b| money_at(b, "fee")))
}

/// `advanced_trade_fill`, when present. Absent (not null) on every other
/// transaction type, so `None` here is the normal case, not a parse failure.
fn fill_detail(row: &Value) -> Option<FillDetail> {
    let f = row.get("advanced_trade_fill")?;
    let get = |k: &str| str_at(f, k).map(String::from);
    let detail = FillDetail {
        product_id: get("product_id"),
        side: get("order_side"),
        fill_price: get("fill_price"),
        commission: get("commission"),
        order_id: get("order_id"),
    };
    // An object that carried none of the fields we read is worth omitting
    // rather than emitting as an empty husk.
    let empty = detail.product_id.is_none()
        && detail.side.is_none()
        && detail.fill_price.is_none()
        && detail.commission.is_none()
        && detail.order_id.is_none();
    (!empty).then_some(detail)
}

/// The human label, preferring `details.title` (+ `details.subtitle`) over the
/// top-level `description`.
///
/// Live reality check (2026-08-13, `CB-VERSION: 2022-01-06`): **`details` never
/// appeared** — not once in a 3,559-row ledger — and `description` exists only
/// on `earn_payout` and `send` rows (a label or a sender memo), absent
/// everywhere else. The `details` preference is kept because the docs attach it
/// to newer API versions, but the fallback is the path that actually runs.
fn description(row: &Value) -> Option<String> {
    let details = row.get("details");
    let title = details.and_then(|d| str_at(d, "title"));
    let subtitle = details.and_then(|d| str_at(d, "subtitle"));
    match (title, subtitle) {
        (Some(t), Some(s)) if !s.is_empty() => Some(format!("{t} {s}")),
        (Some(t), _) => Some(t.to_string()),
        _ => str_at(row, "description").map(String::from),
    }
}

/// `{"amount": "...", "currency": "..."}` at `key`, passed through unmodified.
fn money_at(row: &Value, key: &str) -> Option<Money> {
    let m = row.get(key)?;
    Some(Money {
        amount: str_at(m, "amount")?.to_string(),
        currency: str_at(m, "currency").unwrap_or("").to_string(),
    })
}

/// `currency` is an object (`{"code": "BTC", …}`) on current API versions and a
/// bare string on older ones. Read both.
fn currency_code(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        obj => str_at(obj, "code").map(String::from),
    }
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

/// The `YYYY-MM-DD` prefix of an RFC 3339 timestamp.
///
/// Coinbase timestamps arrive both as UTC (`...Z`) and with an offset
/// (`2015-03-26T13:42:00-07:00`). The date part is taken as written rather than
/// normalized to UTC: it is used for `--since`/`--until` filtering, and
/// silently shifting a user's timestamp by a day would be worse than honouring
/// the offset Coinbase chose to send.
pub fn iso_date(ts: &str) -> Option<String> {
    let d = ts.split('T').next()?;
    let bytes = d.as_bytes();
    if bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-' {
        Some(d.to_string())
    } else {
        None
    }
}

/// Keep only records whose `date` falls within an inclusive ISO range.
///
/// Client-side because the v2 transactions endpoint publishes no date filter —
/// see `docs/api.md`. Cheap string comparison is correct here precisely because
/// ISO `YYYY-MM-DD` sorts lexicographically.
pub fn within<T>(
    items: Vec<T>,
    since: Option<&str>,
    until: Option<&str>,
    date: fn(&T) -> &str,
) -> Vec<T> {
    items
        .into_iter()
        .filter(|it| {
            let d = date(it);
            // An undated record is kept only when the caller asked for no
            // bounds — silently dropping records is worse than showing one
            // that may be out of range, but a bounded query must not include
            // records it cannot place.
            if d.is_empty() {
                return since.is_none() && until.is_none();
            }
            since.is_none_or(|s| d >= s) && until.is_none_or(|u| d <= u)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn currency_reads_both_the_object_and_string_shapes() {
        assert_eq!(
            currency_code(Some(&json!({"code":"BTC","name":"Bitcoin"}))).as_deref(),
            Some("BTC")
        );
        assert_eq!(currency_code(Some(&json!("ETH"))).as_deref(), Some("ETH"));
        assert_eq!(currency_code(None), None);
        assert_eq!(currency_code(Some(&json!(42))), None);
    }

    #[test]
    fn the_description_prefers_details_over_the_null_top_level_field() {
        let row = json!({
            "description": null,
            "details": {"title": "Bought Bitcoin", "subtitle": "using Bank"},
        });
        assert_eq!(
            description(&row).as_deref(),
            Some("Bought Bitcoin using Bank")
        );
        let no_subtitle = json!({"details": {"title": "Sent Ethereum", "subtitle": ""}});
        assert_eq!(description(&no_subtitle).as_deref(), Some("Sent Ethereum"));
        let only_top = json!({"description": "manual note"});
        assert_eq!(description(&only_top).as_deref(), Some("manual note"));
        assert_eq!(description(&json!({})), None);
    }

    #[test]
    fn amounts_are_not_rounded_or_reformatted() {
        let row = json!({"amount": {"amount": "0.00000001", "currency": "BTC"}});
        let m = money_at(&row, "amount").unwrap();
        assert_eq!(m.amount, "0.00000001", "satoshi precision must survive");
        assert_eq!(m.currency, "BTC");
    }

    /// The commission is the reason `fill` exists: a basis figure that ignores
    /// fees is wrong, and no top-level field carries it.
    #[test]
    fn an_advanced_trade_fill_surfaces_its_commission_and_price() {
        let row = json!({
            "id": "t1",
            "type": "advanced_trade_fill",
            "created_at": "2026-02-03T10:00:00Z",
            "amount": {"amount": "0.01000000", "currency": "BTC"},
            "advanced_trade_fill": {
                "fill_price": "50000.00",
                "product_id": "BTC-USD",
                "order_id": "o1",
                "commission": "2.50",
                "order_side": "BUY"
            }
        });
        let t = transaction(&row).unwrap();
        let fill = t.fill.expect("advanced_trade_fill is parsed");
        assert_eq!(fill.commission.as_deref(), Some("2.50"));
        assert_eq!(fill.fill_price.as_deref(), Some("50000.00"));
        assert_eq!(fill.product_id.as_deref(), Some("BTC-USD"));
        assert_eq!(fill.side.as_deref(), Some("BUY"));
    }

    #[test]
    fn a_transaction_without_a_fill_block_omits_it_entirely() {
        let row = json!({"id": "t2", "type": "buy", "amount": {"amount": "1", "currency": "BTC"}});
        let t = transaction(&row).unwrap();
        assert!(t.fill.is_none());
        assert!(t.network_fee.is_none());
        assert!(t.trade_fee.is_none());
        // Omitted, not null — the DTO must not grow noise columns.
        let v = serde_json::to_value(&t).unwrap();
        assert!(v.get("fill").is_none());
        assert!(v.get("network_fee").is_none());
        assert!(v.get("trade_fee").is_none());
    }

    /// `buy.fee` / `sell.fee` is the fee a simple buy/sell itemizes — observed
    /// live 2026-08-13, absent (not null) when Coinbase doesn't itemize one.
    #[test]
    fn a_buy_or_sell_surfaces_its_itemized_fee() {
        let row = json!({
            "id": "t5",
            "type": "sell",
            "amount": {"amount": "-0.05000000", "currency": "BTC"},
            "sell": {
                "fee": {"amount": "7.45", "currency": "USD"},
                "id": "s1",
                "payment_method_name": "Sample USD Wallet",
                "subtotal": {"amount": "500.00", "currency": "USD"},
                "total": {"amount": "492.55", "currency": "USD"}
            }
        });
        let fee = transaction(&row).unwrap().trade_fee.expect("fee parsed");
        assert_eq!(fee.amount, "7.45");
        assert_eq!(fee.currency, "USD");

        // A block without a fee yields None, not a zero-valued husk.
        let no_fee = json!({
            "id": "t6",
            "type": "buy",
            "amount": {"amount": "0.1", "currency": "BTC"},
            "buy": {"id": "b1", "payment_method_name": "Sample Bank"}
        });
        assert!(transaction(&no_fee).unwrap().trade_fee.is_none());
    }

    #[test]
    fn a_send_surfaces_its_network_fee() {
        let row = json!({
            "id": "t3",
            "type": "send",
            "amount": {"amount": "-0.001", "currency": "BTC"},
            "network": {
                "hash": "0000",
                "network_name": "bitcoin",
                "status": "confirmed",
                "transaction_fee": {"amount": "0.00001000", "currency": "BTC"}
            }
        });
        let fee = transaction(&row).unwrap().network_fee.expect("fee parsed");
        assert_eq!(fee.amount, "0.00001000");
        assert_eq!(fee.currency, "BTC");
    }

    #[test]
    fn a_row_with_no_id_is_skipped_rather_than_faked() {
        assert!(account(&json!({"name": "x"})).is_none());
        assert!(transaction(&json!({"type": "buy"})).is_none());
        assert!(accounts(&[json!({}), json!(7)]).is_empty());
    }

    #[test]
    fn iso_dates_come_from_the_timestamp_prefix() {
        assert_eq!(
            iso_date("2015-03-26T13:42:00-07:00").as_deref(),
            Some("2015-03-26")
        );
        assert_eq!(
            iso_date("2026-01-02T00:00:00Z").as_deref(),
            Some("2026-01-02")
        );
        assert_eq!(iso_date("nonsense"), None);
        assert_eq!(iso_date(""), None);
    }

    #[test]
    fn range_filtering_is_inclusive_on_both_ends() {
        let rows: Vec<String> = ["2026-01-01", "2026-06-15", "2026-12-31"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let f = |since: Option<&str>, until: Option<&str>| {
            within(rows.clone(), since, until, |s| s.as_str()).len()
        };
        assert_eq!(f(None, None), 3);
        assert_eq!(f(Some("2026-01-01"), Some("2026-12-31")), 3);
        assert_eq!(f(Some("2026-06-15"), Some("2026-06-15")), 1);
        assert_eq!(f(Some("2026-07-01"), None), 1);
        assert_eq!(f(None, Some("2025-12-31")), 0);
    }

    #[test]
    fn an_undated_record_survives_an_unbounded_query_only() {
        let rows = vec![String::new()];
        assert_eq!(within(rows.clone(), None, None, |s| s.as_str()).len(), 1);
        assert_eq!(
            within(rows, Some("2026-01-01"), None, |s| s.as_str()).len(),
            0
        );
    }
}
