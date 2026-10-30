# Test fixtures

The `fixture_shapes` tests run the parsers in `src/parse.rs` and the pagination
logic in `src/client.rs` against these files, so a Coinbase field rename fails a
test here instead of silently emptying a column.

## These are scrubbed captures

**Captured from a live, authenticated run on 2026-08-13** with
`CB-VERSION: 2022-01-06` (the pin in `src/client.rs`), against a real account,
with a View-only ECDSA CDP key. Structure is real — keys, nesting, key order,
null-vs-absent, sign conventions — and every value is a dummy per the policy
below. The capture walked all 130 accounts and a 3,559-row ledger; each row
kept here is the exemplar of a shape that walk actually produced.

The one deliberate exception: `accounts_last_page.json` keeps the **legacy
string-`currency`** row shape from Coinbase's documentation. The live capture
served only the object shape, but the legacy shape is documented as
version-dependent and is cheap to keep parsing.

Reality corrected the hand-authored predecessors of these files in ways worth
naming, because each one was a plausible bug:

- **`staking_reward` exists** (1,410 rows — the most common type in the
  ledger), despite the docs listing no such type. Reward income arrived under
  four spellings: `staking_reward`, `earn_payout`, `inflation_reward`,
  `interest`. Eight other undocumented types appeared too (`pro_deposit`,
  `pro_withdrawal`, `exchange_deposit`, `exchange_withdrawal`,
  `asset_migration`, `retail_eth2_deprecation`, …).
- **`details` never appeared** — not once — and neither did `updated_at` on any
  transaction row. `description` exists only on `earn_payout` (sometimes the
  empty string) and `send` (a sender memo) rows.
- **Inbound transfers are positive `send` rows** (473 of 499 sends); the
  documented `receive` type never appeared.
- `network` carries `network_name` (undocumented); sends carry an `idem` UUID;
  `buy`/`sell` blocks itemize a `fee` alongside `subtotal`/`total`;
  `to` on an on-chain send is `{address, resource}`.
- Pagination always carried `next_starting_after` and `previous_ending_before`
  alongside the documented fields, and the captured `next_uri` has no `limit=`
  parameter.
- Accounts carry `allow_deposits`, `allow_withdrawals`, `portfolio_id`, and a
  `currency.rewards` object (null unless the asset earns); the documented
  `ready` field never appeared.

## Sources

| File | Endpoint | Provenance |
| --- | --- | --- |
| `accounts.json` | `GET /v2/accounts` (page 1 of N) | live capture 2026-08-13 |
| `accounts_last_page.json` | `GET /v2/accounts` (last page) | hand-authored: legacy string `currency` per docs; pagination shape from live capture |
| `transactions.json` | `GET /v2/accounts/:account_id/transactions` | live capture 2026-08-13 |
| `error_v2.json` | v2 error body | live capture 2026-08-13 (a 404; the shape matches the documented error object) |

What each one is deliberately shaped to exercise:

- **`accounts.json`** — `currency` as an **object** (`.code` must be read, not
  the object itself); `balance.currency` as a **plain string** alongside it; a
  `rewards` object on a staking asset and `null` on the rest; a zero-balance
  wallet, so the default zero-filter has something to hide; a non-null
  `pagination.next_uri` (cursor-only, no `limit=`), so the cursor walk has
  somewhere to go.
- **`accounts_last_page.json`** — `currency` as a **bare string**; a
  one-satoshi balance, so a precision regression fails a test;
  `next_uri: null` to end the walk.
- **`transactions.json`** — one row per captured shape: the four reward-income
  spellings, a `buy` and a `sell` with itemized `fee`/`subtotal`/`total`, an
  `advanced_trade_fill` carrying the `commission` a cost basis needs, a
  `trade`, a `pro_deposit` (negative) and an `exchange_withdrawal` (positive),
  an outbound `send` (memo, `idem`, `network.transaction_fee`, `to.address`)
  and an inbound positive `send` with a `from` block. All timestamps are
  `Z`-suffixed, as captured — the `-07:00` offset form the docs show is pinned
  in `src/parse.rs` unit tests instead.

## Scrubbing policy

**Structure is preserved exactly; every identifying or financial value is an
obvious dummy.** What survives is what the tests are about: field names,
nesting, key order, the string-vs-object `currency` quirk, `null`-vs-absent,
and the sign convention on debits.

Replacements are deliberately unrealistic so a reader can tell at a glance that
a value is fake:

- account ids → `20000000-0000-0000-0000-00000000000N`
- transaction ids → `30000000-…`; order/buy ids → `40000000-…`; user ids →
  `50000000-…`; asset ids → `10000000-…`; portfolio ids → `60000000-…`;
  idem ids → `70000000-…`
- names → `Sample BTC Wallet`, `Sample Sender`, `Sample Bank`
- on-chain hashes → all-zero; addresses → `bc1qdummy000…`
- amounts → round dummies (`1.23450000`, `1000.00`, `50000.00`)
- `currency.color` → `#000000`; APYs → `3.00%`

The rule is enforced **positively** by `fixtures_carry_only_dummy_identifiers`
in `tests/fixture_shapes.rs`: every UUID-shaped string must match the dummy
shape (all zeros but a short tail) and every `address` value must be an obvious
dummy, rather than a denylist of real values — a denylist in a public repo
publishes exactly what it exists to keep out. That test also refuses any
credential-shaped substring (`BEGIN `, `PRIVATE KEY`, `Bearer `, `eyJ`,
`organizations/`).

**Extend that test whenever you add a new kind of identifier.**

## No key material, ever

There is no `.pem` in this directory and there must never be one. The tests
that need a P-256 or Ed25519 key **generate a throwaway one at runtime**
(`throwaway_pem()` in `src/jwt.rs` and `src/credential.rs`). A committed private
key is a gitleaks finding and a habit worth not forming, even when the key
authenticates to nothing.

## Refreshing a fixture

1. Capture the raw response: `cbase api GET /v2/accounts --json`.
2. Cut it to the fragment the parser reads, plus a field or two to prove
   tolerance of extra keys.
3. Apply the scrub map above *consistently* — the same fake account id in every
   file — then `cargo test`.
4. Update the capture date and `CB-VERSION` note above if the capture used a
   different pin.

**Never commit a raw capture "to scrub later."** A Coinbase response carries
account ids, balances, counterparties, and on-chain addresses that tie a real
person to a real wallet forever.
