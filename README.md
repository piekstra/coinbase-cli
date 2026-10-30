# coinbase-cli (`cbase`)

Coinbase accounts and transaction history from the command line — balances, the
full ledger, and the raw material for cost-basis and Form 8949 work.
Keychain-secured, agent-friendly, **read-only**. Unofficial; not affiliated with
Coinbase.

Conforms to the [`piekstra-cli` spec v1](https://github.com/piekstra/cli-common).

> **Status: v0.1.0, built and tested offline. Never run against a real
> Coinbase account.** No authenticated call has ever been made and no account
> data has ever been read by this tool. Every test runs against fixtures
> hand-authored from Coinbase's published API documentation, and the plumbing is
> unit-tested end to end (including signing a JWT and verifying it against its
> own public key). Two *unauthenticated* probes confirmed the transport and the
> error mapping — but a 401 can't tell a malformed token from an unknown key, so
> the JWT construction itself is still unproven. See
> [`docs/api.md` §5](docs/api.md) for the checklist the first real run should
> work through.

## Install

```console
$ cargo install --git https://github.com/piekstra/coinbase-cli
```

or from a clone, which also re-signs the binary so macOS keychain grants survive
a reinstall:

```console
$ make install
```

## First-run setup

**1. Create a CDP API key.** Go to <https://portal.cdp.coinbase.com>, open
**API keys**, and create a new key:

- **Key type: ECDSA.** *Not* Ed25519 — even though the portal defaults to and
  recommends Ed25519, Coinbase separately documents the Coinbase App API as
  supporting ES256 only, and says Ed25519 "may fail". `cbase` supports both and
  warns you if you store an Ed25519 key. See [`docs/api.md` §2.3](docs/api.md).
- **Permissions: View only.** `cbase` never trades or transfers, and a View-only
  key means it *cannot*, whatever the code says.
- Optionally set an IP allowlist.

Download the JSON key file. It looks like:

```json
{ "name": "organizations/<org-uuid>/apiKeys/<key-uuid>",
  "privateKey": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n" }
```

**2. Store it.** Pipe the whole file in — never paste a private key onto a
command line, where it lands in your shell history and the process table:

```console
$ cbase auth set-credential --stdin < ~/Downloads/cdp_api_key.json
CDP API key organizations/…/…4f2a (ES256) stored in the OS keychain (piekstra.cbase)
```

Then delete the downloaded file: `rm ~/Downloads/cdp_api_key.json`.

Use `cbase auth login --stdin < …` instead if you want the key proved against
Coinbase with a live request as it is stored.

**3. Check it.**

```console
$ cbase auth status --verify
```

Exit code 3 means Coinbase rejected the key — usually the wrong key type or a
missing View permission.

**4. Find your accounts.**

```console
$ cbase accounts list
$ cbase config set account <UUID>     # optional default for `transactions list`
```

## Usage

```console
$ cbase accounts list                          # wallets with a non-zero balance
$ cbase accounts list --all                     # include empty wallets
$ cbase transactions list --account <UUID>
$ cbase transactions list --account <UUID> --since 2026-01-01 --until 2026-12-31
$ cbase transactions list --limit 20 --json
$ cbase api GET /v2/accounts                    # raw passthrough (GET only)
$ cbase info                                    # machine-readable capabilities
```

Every command takes `--json`. Human output goes to stdout, diagnostics to
stderr, and each JSON DTO carries a `schema` tag.

### Commands

| Command | What it does |
| --- | --- |
| `auth login\|status\|logout\|set-credential` | CDP API key management (`auth-status/v1`) |
| `config path\|show\|set\|unset` | Non-secret settings (`base_url`, `account`) |
| `accounts list` (alias `ls`, group alias `wallets`) | Wallets and balances (`crypto-account-list/v1`) |
| `transactions list` (alias `ls`) | One wallet's ledger (`crypto-transaction-list/v1`) |
| `api GET <PATH>` | Raw API passthrough, **GET only** |
| `self-update [--check] [-y]` | Update from GitHub releases (`self-update/v1`) |
| `completions <shell>` | Shell completion script |
| `info` | Capability discovery (`cli-info/v1`) |

### Exit codes

`0` ok · `2` usage · `3` auth required or key rejected · `4` not found ·
`5` upstream/Coinbase error or rate limit · `6` refused (a write was attempted)

## Read-only, enforced in code

`cbase` cannot place an order, move funds, or change anything. That is not a
promise in a README — it is a property of the code:

- `client::Coinbase` exposes **no HTTP verb but `GET`**. There is no `post`
  method to call.
- `cbase api` refuses every verb but `GET`, and exits **6**.
- A View-only CDP key means Coinbase would refuse a write anyway.

All three must change together, in the same commit, before this tool ever
writes anything.

## Tax documents: not available via any API

If you came here for 1099-DA / 1099-MISC / gain-loss reports — **Coinbase
publishes no API for them.** This was verified exhaustively against the full CDP
documentation corpus and the legacy v2 reference; there is no endpoint, and no
OAuth scope for one. The forms and the Gain/Loss + Raw Transaction CSVs are
**dashboard-only**, at <https://www.coinbase.com/taxes/documents>.

That is why this CLI has no `documents` command. `transactions list` is the
alternative: it keeps both the asset quantity and Coinbase's fiat valuation,
plus trade commissions and network fees, which is what a Form 8949 line needs.

**But be careful reconciling it.** Coinbase states cost basis is incomplete for
**over 63% of customers** (assets transferred in from elsewhere arrive without
basis), so figures reconstructed from the ledger **will not** match a 1099-DA.
Full details and citations: [`docs/api.md` §1](docs/api.md).

## Security

The CDP private key lives **only** in the OS keychain (service
`piekstra.cbase`, account `api-key`), is read at point of use, and is never
logged, never written to disk by this tool, and never accepted on argv. See
[SECURITY.md](SECURITY.md).

## Development

```console
$ make verify     # fmt-check + clippy -D warnings + tests + smoke — the CI gate
$ make test       # fully offline: no network, no keychain, no credential
$ make dev        # debug build, re-signed so keychain grants survive rebuilds
```

Agent guide: [AGENTS.md](AGENTS.md). API notes and traps: [docs/api.md](docs/api.md).

## License

MIT OR Apache-2.0.
