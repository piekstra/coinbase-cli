# The Coinbase API, as `cbase` uses it

Written from Coinbase's **published documentation** (read 2026-08-11), then
**verified against a live account on 2026-08-13** — the first authenticated
run, with a View-only ECDSA key. Every claim carries its source URL; facts
marked *observed* come from that live run rather than any doc.

> **Status: live-verified.** The JWT auth, both list endpoints, pagination,
> client-side date filtering, the 404 error path, and the v3 Advanced Trade
> read surface have all worked against production. The live run also
> **corrected this document in several places** — the transaction type list is
> longer than documented (`staking_reward` exists; see §3.2), `details` never
> appears, and the pagination block carries undocumented fields. Where a fact
> is still unconfirmed it says so explicitly; §5 lists what remains.

---

## 1. Headline finding: tax documents are NOT available via any API

**This is the fact the tax-cli roadmap needs, so it goes first.**

There is **no documented Coinbase API endpoint** — retail or otherwise — that
returns a 1099-DA, 1099-MISC, 1099-B, a gain/loss report, a cost-basis report,
or a transaction-history CSV export for a retail account. Consequently `cbase`
has **no `documents` command**, and adding one would be building on nothing.

How thoroughly this was established, so nobody re-derives it:

- The entire CDP documentation corpus (`https://docs.cdp.coinbase.com/llms-full.txt`,
  ~13.6 MB) contains **zero** occurrences of `1099` and **zero** of `cost basis`.
  All 272 documented method+path pairs were extracted; filtering for
  `tax|1099|report|document|statement|gain|loss|basis|export|csv` returns three
  hits, all belonging to **Coinbase Exchange** (the institutional product), not
  the retail API.
- The **legacy** v2 reference never had one either: a Wayback snapshot of the
  genuine old `developers.coinbase.com/api/v2` reference contains zero hits for
  `report`, `tax`, `1099`, `cost basis`, and `csv`. A reports resource has never
  existed in the retail v2 API.
- The OAuth2 permission model has **no scope** for tax, reports, or documents —
  so the consent system itself has no concept of them.
  <https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/oauth2/oauth2-permissions>

**The one tax-adjacent endpoint is Exchange-only and is not what it sounds
like.** `POST /reports` on `api.exchange.coinbase.com` accepts
`type=tax-invoice` and `type=1099k-transaction-history`
(<https://docs.cdp.coinbase.com/api-reference/exchange-api/rest-api/reports/create-report>).
But `tax-invoice` is a **trading-fee/VAT invoice**, `1099k-transaction-history`
is supporting history for a **1099-K** (discontinued for US retail since 2021),
and it requires an institutional Exchange account that is separate from the
retail Coinbase app. **No type yields a 1099-DA, 1099-B, 1099-MISC, or a
gain/loss report.**

**Where the documents actually live:** the authenticated web dashboard only, at
<https://www.coinbase.com/taxes/documents> (Documents and Statements tabs).
Forms issued: 1099-MISC (≥$600 income), 1099-DA (from TY2025), 1099-B
(futures/commodities/options). Reports offered: **Gain/Loss Report (CSV)** and
**Raw Transaction Report (CSV** — which *does* include cost basis but does not
compute gains/losses). Download is manual, or via an emailed link.
<https://help.coinbase.com/en/coinbase/taxes/forms-reports/download-report>

### 1099-DA context (why this matters right now)

- TY2025 forms were due to customers **no later than 2026-03-17**.
- Under final regulations **TD 10000**, brokers report **gross proceeds** for
  transactions on/after **2025-01-01**, and **cost basis** to the IRS only for
  transactions on/after **2026-01-01**. So for TY2025 the basis shown to the
  customer is *not* the basis reported to the IRS.
- **Rev. Proc. 2024-28** provides the one-time, irrevocable wallet-by-wallet
  basis-allocation safe harbor, generally effective 2025-01-01.
- Coinbase states cost basis is **incomplete for over 63% of customers**,
  because assets transferred in from outside Coinbase arrive without basis.

Sources: <https://www.coinbase.com/blog/whats-changing-with-crypto-taxes-this-year>,
<https://help.coinbase.com/en/coinbase/taxes/forms-reports/1099da>,
<https://www.coinbase.com/learn/crypto-taxes/whats-new-crypto-tax-regulation>

### What this leaves for a tax pipeline

1. **Reconstruct from the API** — `cbase transactions list` is exactly this, and
   is why the DTO keeps both the asset amount and the fiat valuation, plus the
   `advanced_trade_fill.commission` and the `network.transaction_fee`.
   **Caveat worth stating loudly to any user:** numbers reconstructed this way
   **will not** reconcile with their 1099-DA, because of the >63% incomplete-basis
   problem above. Producing a figure that silently disagrees with the form the
   IRS also received is worse than producing none.
2. **Portal download** — manual, and the only source of the actual forms.
3. **Portal scraping** — undocumented, unstable, and out of scope here.

---

## 2. Authentication: CDP API keys, ES256 JWT per request

> **Observed 2026-08-13: this construction works.** The first authenticated
> request — `cbase auth status --verify` with a freshly created ECDSA
> (View-only) key — was accepted on the first try, and every subsequent call
> (~300 requests across `/v2/accounts`, the transactions walk, and the v3
> probes in §3.5) authenticated with per-request tokens minted exactly as
> described below: SEC1 PEM parsed directly, raw 64-byte `r‖s` signature,
> `nonce` in the header, query-less `uri` claim. The same JWT works for both
> the v2 and v3 surfaces.

### 2.1 Legacy HMAC keys are dead, not deprecated

The old `CB-ACCESS-KEY` / `CB-ACCESS-SIGN` / `CB-ACCESS-TIMESTAMP` scheme is
**gone** for the retail API:

> "Legacy API keys will be expired starting Feb 5, 2025. Users will need to
> migrate to CDP API keys to continue using the Coinbase App API."
> — <https://docs.cdp.coinbase.com/coinbase-app/introduction/changelog> (2025-01-22)

> "In February, 2025, we expired all legacy API keys."
> — <https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/legacy-keys>

Do not confuse this with **Coinbase Exchange** (`api.exchange.coinbase.com`),
where `CB-ACCESS-*` HMAC still exists. Different product, different keys.

### 2.2 What `cbase` sends

Every request carries `Authorization: Bearer <jwt>` plus
`CB-VERSION: 2022-01-06`. The JWT is minted per request in `src/jwt.rs`:

```
header  { "alg": "ES256", "typ": "JWT", "kid": "<key name>", "nonce": "<32 hex chars>" }
claims  { "sub": "<key name>", "iss": "cdp", "nbf": <now>,
          "exp": <now + 120>, "uri": "GET api.coinbase.com/v2/accounts" }
```

signed as a JWS compact serialization with a **raw 64-byte `r || s`**
signature.

Every field above matches Coinbase's own SDK (`coinbase-advanced-py`,
`coinbase/jwt_generator.py`), which is the authoritative reference for this
surface. General docs:
<https://docs.cdp.coinbase.com/get-started/authentication/jwt-authentication>

Facts that matter:

- **`uri` format is `"{METHOD} {HOST}{PATH}"`** — no scheme, and **no query
  string**. A token minted for a path with `?limit=100` glued on does not
  validate. `cbase` keeps the path and the query parameters strictly separate
  for this reason (`Coinbase::get`, `commands::api::split_query`).
- **Lifetime is 120 seconds** and the token is **bound to one method+path**, so
  it is not reusable. `cbase` therefore has **no token cache** — one would be
  expired more often than not.
- **No `aud` claim.** `aud: ["cdp_service"]` belongs to the *CDP Platform* API
  at `api.cdp.coinbase.com` (<https://docs.cdp.coinbase.com/api-reference/v2/authentication>),
  a different product. Sending it here is wrong.
- **`nonce` is a JOSE *header* parameter**, not a claim.

### 2.3 Key types — use ECDSA, not Ed25519

Coinbase issues two key types, and the guidance is genuinely contradictory:

| Type | JWT `alg` | Private key format |
| --- | --- | --- |
| **ECDSA (P-256)** | `ES256` | PEM, `-----BEGIN EC PRIVATE KEY-----` (**SEC1**) |
| **Ed25519** | `EdDSA` | base64, 64 bytes = 32-byte seed ‖ 32-byte public key |

The CDP portal **defaults to and recommends Ed25519**:

> "ECDSA is a legacy key algorithm. You should use Ed25519 instead."
> — <https://docs.cdp.coinbase.com/get-started/authentication/jwt-authentication>

…but the Coinbase App surface documents the opposite:

> "When using Coinbase App SDKs, Ed25519 (EdDSA) keys are **NOT** supported. You
> must use ES256 key format." … "If you select Ed25519, your authentication
> attempts may fail."
> — <https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/api-key-authentication>

**Create an ECDSA key.** That is the documented-safe path for
`api.coinbase.com`. `cbase` implements both — so a key of either type works if
Coinbase changes this — and **warns on stderr** when an Ed25519 key is stored,
because otherwise the failure mode is a key that saves cleanly and 401s on
first use, which is miserable to debug.

*(Unconfirmed: whether `api.coinbase.com` genuinely rejects EdDSA JWTs. The
restriction as written is scoped to *SDKs*, and Coinbase's own Python SDK does
support Ed25519. Not testable offline.)*

### 2.4 Why the JWT is hand-rolled

`src/jwt.rs` assembles the token directly rather than using `jsonwebtoken`.
This was a considered choice — recording it so it isn't re-litigated:

- The historical blocker (no `nonce` header field) **is gone** — `jsonwebtoken`
  has had a native `Header::nonce` since 10.0.0. That is *not* the reason.
- **`EncodingKey::from_ec_pem` accepts PKCS#8 only**, while Coinbase ships
  **SEC1**. Using it means converting every key
  (`SecretKey::from_sec1_pem` → `to_pkcs8_der` → `from_ec_der`) before each use.
  `p256::SecretKey::from_sec1_pem` reads Coinbase's key directly, so `cbase`
  simply has no conversion step. (It accepts PKCS#8 too, for keys someone has
  round-tripped through a conversion tool.)
- **`jsonwebtoken 11` internally pins `p256 0.13` and `ed25519-dalek 2.1`.**
  Depending on it would put a *second major version* of both crypto crates in
  the graph next to the `p256 0.14` / `ed25519-dalek 3.0` used directly, with
  non-interchangeable types across the boundary.
- Ed25519 via `jsonwebtoken` also requires hand-splicing a PKCS#8 prefix onto
  the raw seed. `ed25519_dalek::SigningKey::from_keypair_bytes` instead loads
  the 64-byte blob **and validates that the two halves agree**, catching a
  corrupted key at load rather than emitting signatures Coinbase rejects.
- It is ~40 lines, and being in-tree means the whole path is unit-tested
  offline — including signing a token and **verifying it against its own public
  key**, which is the only real proof available without a live request.

Alternative if this ever needs revisiting: **`josekit`** is the one crate that
eats Coinbase's SEC1 PEM as-is (at the cost of a system OpenSSL dependency). If
you use it, do **not** call `JwsHeader::set_nonce()` — it base64url-encodes its
argument and would double-encode a hex nonce; use
`set_claim("nonce", …)` on the header instead.

There is an official **`cdp-sdk` 0.7.0** Rust crate
(<https://github.com/coinbase/cdp-sdk>, `rust/`), but it targets
`api.cdp.coinbase.com` — its claims use `aud` and `uris[]`, not `uri` — so it is
not drop-in for this surface. It also feeds a SEC1 PEM to `from_ec_pem`, which
rejects SEC1; don't cargo-cult it.

### 2.5 The ES256 signature-encoding trap

JWS requires the signature as **fixed-width raw `r || s`, 64 bytes**, *not* the
ASN.1 DER that OpenSSL emits by default. `ecdsa::Signature::to_bytes()` gives
exactly this; `to_der()` must never be used for a JWS. Getting it wrong produces
a 401 that looks exactly like a bad key. `es256_token_has_the_header_and_claims_coinbase_requires`
asserts the 64-byte length specifically to pin this.

### 2.6 Key permissions

Create the key with **View** only.
<https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/authorization>

> **View** — "Allows your application to read user data such as account
> balances, transaction history, and profile information."
> **Trade** — "Grants permission to execute buy and sell orders…"
> **Transfer** — "Enables your application to send and receive funds…"

`cbase` never needs Trade or Transfer, and a View-only key means a bug in this
tool cannot move money regardless of what the code says. Setting an IP allowlist
in the portal is also worth doing.

### 2.7 OAuth2 is not an option

`login.coinbase.com/oauth2/auth` exists, but: *"OAuth client creation is
currently limited to approved partners."* Not viable for a personal CLI.
<https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/oauth2/oauth2>

### 2.8 `CB-VERSION` is required

<https://docs.cdp.coinbase.com/coinbase-app/api-architecture/versioning>

The v2 API is date-versioned via a `CB-VERSION: YYYY-MM-DD` header. Omit it and
Coinbase falls back to the version the *key* was created against and emits a
warning — meaning two users running the same binary can get different shapes.

> "Do not pass in the current date, as that will return the current version
> which might break your implementation."

`cbase` pins `2022-01-06` (`client::CB_VERSION`), the literal date from
Coinbase's own example. **Verified live 2026-08-13:** under this pin, responses
match `tests/fixtures/` (which are now captures taken under it). Two
version-dependent quirks observed under this pin specifically: `currency`
arrives as an **object**, and the `details` block **never arrives** (§3.2). If
responses ever disagree with the fixtures, check this pin first, and bump it in
the same commit as the fixtures.

---

## 3. Endpoints

Base host: `https://api.coinbase.com`.

### 3.1 `GET /v2/accounts` — wallets and balances

<https://docs.cdp.coinbase.com/coinbase-app/track-apis/accounts> · scope
`wallet:accounts:read` · used by `cbase accounts list`

Query: `limit` (0–100, default **25**), `order` (`asc`|`desc`, default `desc`),
`starting_after`, `ending_before`.

Response shape: `{"pagination": {...}, "data": [...]}`. Observed row shape
(130 accounts, 2026-08-13, uniform across all of them): `id`, `name`,
`primary`, `type` (`wallet`|`fiat`|`vault`), `balance`, `created_at`,
`updated_at`, `resource`, `resource_path`, `currency`, plus three fields the
docs don't list — **`allow_deposits`**, **`allow_withdrawals`**, and
**`portfolio_id`** (a UUID; presumably the v3 portfolio, untested). The
documented sometimes-present `ready` field never appeared. All timestamps were
`Z`-suffixed.

The observed `currency` object is
`{asset_id, code, color, exponent, name, slug, type, rewards}` — always all
eight keys, with **`rewards`** null except on staking assets, where it is
`{"apy": "0.0446", "formatted_apy": "4.46%", "label": "…"}`. The documented
`address_regex`/`sort_index` fields did not appear.

**Two traps in one object:**
- `currency` is an **object** on current API versions and a **bare string** on
  older ones (documented; only the object shape was observed under the pinned
  `CB-VERSION`). `parse::currency_code` reads both;
  `the_legacy_string_currency_shape_still_parses` pins it.
- `balance.currency` is a **plain string** even when the sibling `currency` is
  an object (observed). Reading one as the other yields an empty column.

### 3.2 `GET /v2/accounts/:account_id/transactions` — the ledger

<https://docs.cdp.coinbase.com/coinbase-app/track-apis/transactions> · scope
`wallet:transactions:read` · used by `cbase transactions list`

**There are no date-filter query parameters.** The docs publish no parameter
table for this endpoint, and the OAuth2 endpoint inventory lists no filters —
only the generic pagination parameters apply. So `--since`/`--until` in `cbase`
are applied **client-side** after paging (`parse::within`). On a long history
that is a real cost, and it is why `--limit` exists. It is also why
`transactions::fetch_limit` refuses to push `--limit` down to the fetch when
dates are given: the wanted records may be anywhere in the history, and stopping
early would silently return a prefix of the wrong range.

Observed row shape (3,559 rows across all 130 accounts, 2026-08-13): `amount`
`{amount, currency}`, `created_at`, `id`, `native_amount` `{amount, currency}`
(present on **every** row, always USD here), `resource`, `resource_path`,
`status`, `type`, plus conditional fields. **`updated_at` never appeared**, and
neither did `details` — both documented. `description` appeared only on
`earn_payout` rows (a label, sometimes the **empty string**) and some `send`
rows (a sender memo); on every other row the key is absent.

**Traps:**
- **`details` does not exist in practice** (0 of 3,559 rows under
  `CB-VERSION: 2022-01-06`), despite the docs putting the human label in
  `details.title`. `parse::description` still prefers `details` in case newer
  API versions send it, but the fallback to top-level `description` is the
  path that actually runs — and that is usually absent too. Expect unlabeled
  rows; the `type` column is the real signal.
- **`to` / `from` / `network` / `description` are absent, not null,** when not
  applicable (observed).
- **Amounts are signed**; debits are negative (observed: 741 negative rows).
  Dropping the sign turns a disposal into an acquisition. The sign conveys
  direction, not semantics — `buy`, `exchange_deposit`, and `pro_deposit` rows
  all appeared with negative amounts.
- **Timestamps**: the docs show both `Z` and numeric offsets
  (`2015-03-26T13:42:00-07:00`); the live capture was 100% `Z`.
  `parse::iso_date` still takes the date part as written rather than
  normalizing to UTC, so a user's own timestamp is never shifted by a day.

**The documented type list is incomplete.** The docs list 29 values; a single
real account's history contained **nine types that are not on that list**:

> observed, undocumented: `staking_reward` (1,410 rows — the most common type
> in the entire ledger), `interest` (317), `pro_deposit` (282),
> `exchange_withdrawal` (164), `inflation_reward` (156), `pro_withdrawal` (89),
> `exchange_deposit` (40), `asset_migration` (2), `retail_eth2_deprecation` (2)
>
> observed, documented: `send` (499), `fiat_withdrawal` (234), `trade` (158),
> `sell` (74), `advanced_trade_fill` (68), `earn_payout` (20), `buy` (16),
> `tx` (15), `fiat_deposit` (7), `staking_transfer` (4), `wrap_asset` (2)

Two corrections the live run forced on this document:

> **`staking_reward` exists.** An earlier revision of this file said the
> opposite — "there is no `staking_reward`, staking income is `earn_payout`" —
> reasoning from the documented list. Reality: **both exist**, and
> `staking_reward` outnumbers `earn_payout` 70:1. Reward income arrived under
> **four spellings** — `staking_reward`, `earn_payout`, `inflation_reward`,
> `interest` — and an income filter must match all of them or it silently
> underreports. `reward_income_arrives_under_four_spellings` pins it.
> (`staking_transfer`/`unstaking_transfer` remain principal movements, not
> income.)

> **Inbound transfers arrive as positive `send` rows** — 473 of the 499 sends
> were inbound (positive, usually with a `from` block); the documented
> `receive` type never appeared. Treating `send` as always-outgoing
> misclassifies received assets.

This is exactly why `cbase` passes `type` through verbatim and never validates
it against a list: an entry this tool silently dropped is an entry missing
from a tax return.

**`status` values (documented):** `canceled`, `completed`, `expired`,
`failed`, `pending`, `waiting_for_clearing`, `waiting_for_signature`. The
entire live capture contained only `completed`.

**Conditional blocks, as observed:**

- `advanced_trade_fill`: `{commission, fill_price, order_id, order_side,
  product_id}` — exactly as documented; `commission` is in the quote currency.
- `buy` / `sell`: `{fee, id, payment_method_name, subtotal, total}` — with
  **`fee`** (Money-shaped) present only when Coinbase itemizes one (6 of 90
  blocks). The docs never mention `fee`; it is a real cost-basis input.
- `trade`: `{id, payment_method_name}` only.
- `network` (on every `send`): `{hash, network_name, status}` plus
  `transaction_fee` on outbound on-chain sends. **`network_name` is
  undocumented**; the docs' spelling `name` was never observed.
- `to` on an outbound on-chain send: `{address, resource}`; `from` on an
  inbound send: `{id, name, resource}`.
- `send` rows also carry an undocumented **`idem`** UUID.

`cbase` surfaces `advanced_trade_fill` as `fill`, `network.transaction_fee` as
`network_fee`, and `buy.fee`/`sell.fee` as `trade_fee`, because **a cost basis
that ignores fees is wrong** and no top-level field carries any of them.

### 3.3 Pagination — terminate on `next_uri`

<https://docs.cdp.coinbase.com/coinbase-app/api-architecture/pagination>

The documented block is:

```json
{"ending_before": null, "starting_after": null, "limit": 25, "order": "desc",
 "previous_uri": null, "next_uri": null}
```

The **observed** block (every page, both endpoints, 2026-08-13) carries two
extra fields — `next_starting_after` and `previous_ending_before` — and the
observed `next_uri` has **no `limit=` parameter**, just
`?starting_after=<id>`:

```json
{"ending_before": null, "limit": 25,
 "next_starting_after": "<id>", "next_uri": "/v2/accounts?starting_after=<id>",
 "order": "desc", "previous_ending_before": null, "previous_uri": null,
 "starting_after": null}
```

**Stop when `next_uri` is null.** `next_starting_after` is not part of the
documented contract, even though it accompanied `next_uri` on every observed
page — a fixture authored from one capture could wrongly conclude it is
reliable alone. Reading only that field is a **silent-truncation bug** the day
Coinbase drops it: page one arrives, the field is absent, the walk stops, and a
partial ledger is reported as a complete one. `client::next_cursor` parses
`starting_after=` out of `next_uri` and falls back to `next_starting_after`
only if present; `the_cursor_comes_out_of_next_uri` pins it. The walk also
refuses a cursor that doesn't advance, so a provider bug can't spin it forever.
The full-ledger walk (85 pages) paged correctly and terminated.

### 3.4 Deprecated / not used

- **Buys and Sells** (`/v2/accounts/:id/buys`, `/sells`) — the doc pages are
  titled "(Deprecated)" and they are absent from the OAuth2 endpoint inventory.
  Don't build on them; the same events appear in `transactions` anyway.
- **Deposits and withdrawals** (`/v2/accounts/:id/deposits`, `/withdrawals`) are
  live and could be added later; the ledger already reflects them as
  `fiat_deposit` / `fiat_withdrawal`.

### 3.5 Not implemented, but high value — the v3 Advanced Trade surface

**Live-verified 2026-08-13: the same CDP key and the same JWT construction
authenticate against v3.** Both probes below succeeded via
`cbase api GET <path>` with the View-only key.

- **`GET /api/v3/brokerage/portfolios`** — observed:
  `{"portfolios": [{name, uuid, type, deleted}]}`.
- **`GET /api/v3/brokerage/portfolios/{uuid}?currency=USD`** — the portfolio
  breakdown, observed live. `breakdown` carries `portfolio`,
  `portfolio_balances`, `spot_positions`, plus `equity_positions`,
  `futures_positions`, `perp_positions`, and `prediction_markets_positions`
  (the last four undocumented or newer than the docs read). Each
  `spot_positions[]` entry includes **`cost_basis`** and
  **`average_entry_price`** — both `{value, currency}` — alongside
  `total_balance_fiat`/`total_balance_crypto`, `unrealized_pnl`, and
  friends. This is *Coinbase's own* cost-basis number, which makes it the
  natural reconciliation check against anything computed from the ledger.
  **Note the mixed number representations:** money objects are
  `{value, currency}` with string values, but `total_balance_fiat`,
  `allocation`, and `unrealized_pnl` are **JSON floats** — anything consuming
  these for tax math must prefer the string-money fields.
  <https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/portfolios/get-portfolio-breakdown>
- **`GET /api/v3/brokerage/orders/historical/fills`** — untested, but **this
  one does have date filters** (`start_sequence_timestamp` /
  `end_sequence_timestamp`, RFC 3339), unlike the v2 ledger. Fields:
  `trade_id`, `order_id`, `trade_time`, `price`, `size`, `commission`,
  `product_id`, `side`.
  <https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/orders/list-fills>

Note that v3 is a **different dialect**: money is `{value, currency}` (not
`{amount, currency}`), accounts are keyed `uuid` (not `id`), and pagination is
`has_next`/`cursor`/`size` (not a `pagination` object). Anything built on v3
needs its own parsers; it cannot reuse `src/parse.rs`.

---

## 4. Errors and limits

### The 401 body is NOT JSON — observed, not documented

**Trap, confirmed live on 2026-08-12.** A rejected request to
`GET /v2/accounts` does not return the documented JSON error object. It returns:

```
HTTP/2 401
content-type: text/plain; charset=utf-8
content-length: 13

Unauthorized
```

Both an unauthenticated request and one bearing a well-formed JWT for an
unregistered key produce exactly this. Consequences:

- **Anything that calls `.json()` on an error response will fail to parse it**
  and report a deserialization error instead of "your key was rejected". This is
  precisely why `cbase` does not use `pk_cli_http::json_response`;
  `client::response_json` reads the body as text and only opportunistically
  parses JSON.
- **A 401 does not distinguish a malformed JWT from an unregistered key.** Both
  give the same opaque plain-text response, so reaching a 401 proves the
  transport, headers, and error mapping work — it does *not* validate the JWT
  construction. That still needs a real key.
- The `trace-id` response header is the only correlator Coinbase gives you here;
  quote it if you ever open a support ticket.

### v2 error body (documented shape, for other statuses)

<https://docs.cdp.coinbase.com/coinbase-app/api-architecture/error-messages>

```json
{"errors": [{"id": "not_found", "message": "Not found"}]}
```

> "Except for `validation_error`, all error messages return only one error."

**Observed live 2026-08-13:** a GET for a nonexistent account id answered a
404 with exactly this shape (`id: "not_found"`, `message: "Not Found"`), and
`cbase` mapped it to exit 4 with Coinbase's message. So the documented JSON
error object is real for non-401 statuses — the plain-text body above is
specific to the 401 path.

| `id` | HTTP |
| --- | --- |
| `param_required`, `validation_error`, `invalid_request`, `two_factor_required`, … | 400 |
| `authentication_error`, `invalid_token`, `revoked_token`, `expired_token`, `unauthorized` | **401** |
| `invalid_scope` | **403** |
| `not_found` | 404 |
| `rate_limit_exceeded`, `resource_exhausted` | 429 |
| `internal_server_error` | 500 |

`client::response_json` maps these onto the family exit codes: **401 → auth (3)**
with "check the key", **403 → auth (3)** but with a *scope/permission* message
because that is a different fix, **404 → not found (4)**, **429 → upstream (5)**
with a rate-limit hint, everything else → **upstream (5)**. It prefers
Coinbase's own message over the status line — "HTTP 400 from provider" is a much
worse error than the one Coinbase already wrote.

This is why `cbase` does **not** use `pk_cli_http::json_response`: that helper
maps 403 to the same message as 401, and cannot see the `errors[]` body.

### v3 error body

Not formally documented anywhere. The expected shape is Google-API style:
`{"error": …, "code": …, "message": …, "error_details": …}`.
`client::v3_error_message` reads it permissively and is only consulted when the
v2 shape is absent. **Observed once, live 2026-08-13:** a GET for a bogus
portfolio uuid answered **403** and the permissive reader extracted Coinbase's
message ("User does not have access to portfolio"), which `cbase` mapped to
exit 3 with the scope-flavored message. The exact raw body wasn't logged, but
the reader demonstrably handles the real shape.

Do **not** reuse the CDP *Platform* error shape
(`{"errorType", "errorMessage", "correlationId", …}`,
<https://docs.cdp.coinbase.com/api-reference/v2/errors>) — that is
`api.cdp.coinbase.com`, a different product whose "v2" naming collides
confusingly with this one.

### Rate limits

**10,000 requests/hour** per API key for the Coinbase App API.
<https://docs.cdp.coinbase.com/coinbase-app/api-architecture/rate-limiting>

Responses carry `x-ratelimit-limit`, `x-ratelimit-remaining`, and
`x-ratelimit-reset`; trust those over any hardcoded number. The commonly cited
"30 rps" figure for Advanced Trade traces to a retired docs page and could not
be confirmed on any live official page — treat it as unverified. Coinbase
**Exchange** limits are different again and do not apply here.

---

## 5. The first-live-run checklist — mostly settled 2026-08-13

The first authenticated run worked through the original checklist. Settled:

1. ✅ **The whole request authenticates.** First try, ECDSA View-only key;
   ~300 requests over two days of session work, v2 and v3 both. (§2)
2. ✅ **`CB-VERSION: 2022-01-06`** returns the shapes now captured in
   `tests/fixtures/` — after the fixtures were corrected from reality; the
   hand-authored versions were wrong in ways §3.1–§3.3 record.
3. ✅ **The v3 error shape** — observed once (403), parsed correctly. (§4)
4. ✅ **`next_starting_after` appears in practice** — on every page, alongside
   `next_uri`, plus the undocumented `previous_ending_before`. (§3.3)

Still unverified:

1. **Whether `nonce` is strictly enforced.** `cbase` always sends it; proving
   enforcement would mean deliberately omitting it, which needs a code change
   and burns nothing worth learning — every request simply includes it.
2. **Whether an Ed25519 key really fails** against `api.coinbase.com`. The
   live key is ECDSA (the documented-safe choice); testing this needs a
   second, Ed25519 key and a willingness to watch it 401.
3. **Advanced Trade rps limits** — no rate-limit response was ever observed,
   including during the 300-request ledger walk.
4. **`GET /api/v3/brokerage/orders/historical/fills`** — the date-filtered
   fills feed; untested, high value for tax work. (§3.5)

When any of these is settled, update this file *and* the fixtures in the same
commit, and record the capture date in `tests/fixtures/README.md`.
