# AGENTS.md — working on `cbase`

The canonical agent guide for this repo. `CLAUDE.md` points here.

## What this is

A piekstra-family CLI (spec `piekstra-cli/1`) over the **Coinbase App API** at
`api.coinbase.com`. Thin layer over the shared `pk-cli-*` crates from
[cli-common](https://github.com/piekstra/cli-common), pinned to tag **v0.15.1**.

Binary `cbase`, crate `coinbase-cli`, lib `cbase`. The library builds two
ways: feature `native` (the default) is everything the binary needs, and
`--no-default-features --features wasm` builds it for `wasm32-unknown-unknown`
as the MCP tools' WebAssembly module, released as `cbase-mcp-<version>.wasm`
for cli-common's deploy-your-own Cloudflare connector. Same tools, client,
signer and parsers; only the transport differs (`pk_cli_core::transport`:
blocking reqwest natively, the Worker's `fetch` and WebCrypto in the module).

## The one thing to understand first

**This CLI is live-verified as of 2026-08-13.** The first authenticated run —
a View-only ECDSA CDP key, created for the purpose — proved the hand-rolled
JWT on the first request, walked all 130 accounts and a 3,559-row ledger, and
exercised the v3 Advanced Trade read surface with the same token construction.
The fixtures are now **scrubbed captures** from that run, not hand-authored
guesses.

That run also demonstrated why live verification was worth it — the documented
reality and the actual reality disagreed in ways that would have produced
wrong tax numbers (see the traps below and `docs/api.md`): `staking_reward`
exists despite the docs, reward income has four spellings, `details` never
appears, and inbound transfers are positive `send` rows.

Practical consequences:

- `docs/api.md` §5 still lists what remains unverified (nonce enforcement,
  Ed25519 rejection, v3 fills, rate limits). When something on it is settled,
  update `docs/api.md` **and** the fixtures **and**
  `tests/fixtures/README.md` in the same commit.
- `CB-VERSION` (`src/client.rs`) is now verified: the captured shapes belong
  to `2022-01-06`. Bumping it invalidates the fixtures — bump both together.

## Layout

| Path | What lives there |
| --- | --- |
| `src/main.rs` | clap tree, `auth`/`config` commands, exit-code mapping |
| `src/client.rs` | HTTP client (GET only) over any `Transport`, pagination, error→exit-code mapping |
| `src/jwt.rs` | CDP JWT minting: ES256 and EdDSA, by hand; the signing input apart so a platform signer can sign it |
| `src/credential.rs` | Parsing the CDP key file; masking; the no-leak `Debug`; the keychain and environment sources (`native`) |
| `src/config.rs` | Non-secret settings |
| `src/parse.rs` | Coinbase JSON → DTOs |
| `src/commands/` | One module per command group |
| `src/mcp.rs` | The MCP tools (`coinbase_accounts`, `coinbase_transactions`) over the same client and DTOs, behind the `Source` seam: `LiveSource` for `cbase mcp`, `ClientSource` for the Worker |
| `src/worker.rs` | The Worker module (`wasm`): the toolset per call from the Worker's secrets, exported with `pk_cli_mcp::export_wasm!` |
| `scripts/check-wasm.mjs` | Checks a built module against the host's ABI before it is published (`make wasm`, the release workflow) |
| `packaging/mcpb/manifest.json` | The Claude Desktop extension manifest; the release workflow packs `cbase-<version>.mcpb` from it |
| `tests/cli_surface.rs` | Black-box: help, exit codes, the read-only guard |
| `tests/fixture_shapes.rs` | Contract tests over `tests/fixtures/` |
| `tests/mcp_tools.rs` | Every MCP tool in process over the fixtures, plus cli-common's conformance check |
| `tests/mcp_stdio.rs` | The real `cbase mcp` binary driven over stdio |
| `tests/worker.rs` | The Worker module through its ABI, natively (`--features wasm`), with every JWT verified |
| `tests/packaging.rs` | The `.mcpb` manifest against the code: version, tools, env vars |

## Non-negotiables

**Read-only, enforced in three places that must agree.** `client::Coinbase`
exposes no verb but `GET`; `commands::api` refuses everything else with exit 6;
the README and this file say so. Adding a write means changing all three in one
commit — and reconsidering whether this tool should do it at all. The MCP tools
are `ToolDef::read`s over the same client; a write tool would also have to be
its own `ToolDef::write` (never mixed into a read), and none may move money.

**The private key is a secret.** Keychain (`piekstra.cbase`, account
`api-key`), ingested via `--stdin`/`--from-env`, never argv, never a file in the
repo, never a log line. The one other source is the environment pair
`CBASE_API_KEY_NAME` + `CBASE_API_PRIVATE_KEY` (`credential::resolve_key`),
which wins over the keychain and is how the Claude Desktop extension passes
the key from its own secure store; half a pair is exit 3, never a fall-back.
The Worker module reads the same two names from the Worker's secrets
(`credential::key_from_parts`) and has no other source. `Credential` has a hand-written `Debug` so a stray
`{:?}` can't leak it — don't derive `Debug` over key material.

**No key material in the repo.** Tests that need a key generate a throwaway one
at runtime. There must never be a `.pem` in `tests/fixtures/`.

**Validate before touching the keychain or the network.** Every command
validates its arguments first, so `--help` and bad input never prompt, hang, or
spend a request. The exit-code tests in `tests/cli_surface.rs` exist to catch a
regression here.

**MCP tools never sign in.** A tool call never prompts, never starts a login
and never creates a keychain item; a missing or rejected key is an `auth`
error telling the model to have the user run `cbase auth login` in a terminal
(in the Worker: to update the Worker's secrets; pk-cli-mcp's `InWorker`
rewrites the wording, and the 401 hint is only added natively).
`tools/list` touches no credential: the key is read on the first call and
kept for the life of the server.

**The module stays host-neutral.** Nothing under `wasm` may reach the clock,
randomness or network except through pk-cli-mcp's host (`pk_cli_mcp::wasm`),
and the module may import nothing but `pk_host`: `scripts/check-wasm.mjs`
fails the build otherwise. The client takes the network from its transport
and the clock, randomness and warnings from a `client::Platform`, both
chosen where it is built: `Platform::system()` in `Coinbase::with_key`, the
Worker's host functions in `worker::client`. Nothing below those two picks
a platform itself. A dependency that pulls `getrandom` or
`wasm-bindgen` into the wasm32 build breaks the Worker; p256 is built
without `std` there for that reason.

**Exactly one JSON document per invocation.** `auth status --verify` emits its
DTO then calls `std::process::exit` directly rather than returning an error,
which would print a second document after it.

**Amounts are strings, passed through verbatim.** Never parse a crypto amount
into a float, never reformat to two decimals. A BTC balance has eight decimal
places and a basis calculation is only as good as its digits.

## Traps that have already cost time

Full detail and citations in `docs/api.md`. The short list:

1. **Pagination terminates on `next_uri`, not `next_starting_after`.** The
   latter isn't in the documented contract — even though the live capture saw
   it on every page. Reading only it truncates a ledger silently the day
   Coinbase drops it — a partial financial history reported as a complete one.
   This was a real bug in the first draft.
2. **Reward income has FOUR spellings**: `staking_reward` (the most common,
   despite being absent from Coinbase's documented type list), `earn_payout`,
   `inflation_reward`, `interest`. An earlier revision of this file asserted
   `staking_reward` doesn't exist — the first live capture refuted it 1,410
   rows to 20. Filter for all four or underreport income.
3. **`details` never appears, and `description` almost never** (live:
   0 and ~1.4% of 3,559 rows). The `type` column is the real signal; don't
   build anything that needs a human label per row.
4. **Inbound transfers are positive `send` rows** — the documented `receive`
   type never appears. `send` is a direction-neutral type; the sign is the
   direction.
5. **The JWT `uri` claim must not contain a query string**, and is
   `"{METHOD} {HOST}{PATH}"` with no scheme. Glue `?limit=100` on and you get a
   401 that looks exactly like a bad key.
6. **ES256 JWS signatures are raw 64-byte `r || s`, not DER.** Also a 401 that
   looks like a bad key. (Both JWT constructions are live-proven as of
   2026-08-13; if auth breaks, suspect the key or Coinbase before this code.)
7. **Use an ECDSA key, not Ed25519** — the CDP portal recommends Ed25519, the
   Coinbase App API docs say it isn't supported. `cbase` warns on store.
8. **`currency` is an object on new API versions and a string on old ones**, and
   `balance.currency` is a plain string either way.
9. **403 ≠ 401.** 403 means the key lacks a scope (fix: re-create the key); 401
   means the key is bad. They map to different messages deliberately. Both
   observed live: 401 is `text/plain`, 403/404 carry the JSON error body.

## Dev loop

```console
$ make verify     # fmt-check + clippy -D warnings (with and without `wasm`) + test + wasm32 clippy + smoke
$ make wasm       # the Worker module, checked against the host ABI (needs Node)
$ make dev        # debug build, re-signed with the stable identity
$ make install    # installs AND re-signs — `cargo install` alone re-prompts the keychain
```

CI (`.github/workflows/ci.yml`) runs every step of `make verify` except
`smoke`, plus a release build, `make wasm`, and a cargo-audit / cargo-deny /
gitleaks job.

To try a module change in the connector before releasing it, build it with
`make wasm` and point cli-common's `connector/` at the file
(`CONNECTOR_MODULE_COINBASE=<path> npm run e2e` there).

Tests are **fully offline** and must stay that way: no network, no keychain, no
credential. Nothing in the suite should ever spend a Coinbase request.
Hermeticity is enforced by `CBASE_KEYCHAIN_SERVICE`: the `cli_surface` and
`mcp_stdio` suites point it at a service that holds nothing, so the exit-3
cases stay true even on a machine with a real key stored — without it,
`cargo test` opens the developer's actual credential from an ad-hoc-signed
binary (a macOS approval prompt per rebuild) and then hits Coinbase for real.
Found the hard way on the first live run. `tests/mcp_tools.rs` reaches no client at all: it runs the
tools over a fixture `Source`.

`make smoke` never reads the real keychain either. Its one keychain-reading
step, `auth status`, runs from the release binary with
`CBASE_KEYCHAIN_SERVICE=piekstra.cbase.hermetic-tests`, the same empty service,
so `make verify` raises no keychain dialog whatever the binary's code identity.
Its other steps (`--version`, `--help`, `info`, `mcp --list-tools`) read no
key. A new smoke step that can reach the keychain carries the same override.

## Working with the live credential

A real View-only key lives in the keychain (`piekstra.cbase`) since
2026-08-13. Dogfood through the **installed** binary (`make install` — signed,
so the keychain grant sticks); reinstall after every fix — a stale
`~/.cargo/bin/cbase` will happily serve old behavior. Prefer
`cbase api GET <path>` over curl for exploration: it exercises the real
signing path. `docs/api.md` §5 lists what is still unverified. To dogfood the
MCP tools, drive the installed `cbase mcp` over stdio with JSON-RPC lines
(`initialize`, `tools/list`, `tools/call`); `cbase mcp --list-tools` prints
the definitions without a credential. Never paste
real output into fixtures un-scrubbed; `tests/fixtures/README.md` has the
policy.

## Follow-ups

- **Register in `cli-mcp`** (`~/Dev/open-cli-mcp/cli-mcp`) — deliberately not
  done here; handled centrally.
- **macOS CI job.** CI runs on Linux only (this is a private repo and macOS
  runners bill ~10×). The apple-native keychain backend's *runtime* behavior is
  therefore untested in CI; there's a note in `.github/workflows/ci.yml`
  describing the targeted job to add if that gap ever bites.
- **v3 Advanced Trade**: `portfolios/{uuid}` exposes Coinbase's *own*
  `cost_basis` and `average_entry_price`, and `orders/historical/fills` has real
  date filters. Both are high-value for tax work and reachable today via
  `cbase api`. Note v3 is a different dialect (`{value, currency}`, `uuid`,
  `has_next`/`cursor`) and needs its own parsers.
