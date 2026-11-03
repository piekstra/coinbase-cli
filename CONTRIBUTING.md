# Contributing to coinbase-cli

Thanks for your interest! Contributions — bug reports, fixes, new commands,
docs — are welcome under the project's dual [MIT](LICENSE-MIT) /
[Apache-2.0](LICENSE-APACHE) license: by opening a pull request you agree your
contribution is licensed under those same terms.

## Ground rules (this reads a real person's financial history)

- **Never commit secrets or personal data.** The CDP API key lives only in the
  OS keychain. Nothing credential-like or personal belongs in the repo, tests,
  fixtures, or commit messages.
- **Never commit key material — not even a throwaway PEM.** Tests that need a
  key generate one at runtime. There must never be a `.pem` in the tree.
- **Fixtures are scrubbed live captures, with dummy values only.** They were
  captured on 2026-08-13. [`tests/fixtures/README.md`](tests/fixtures/README.md)
  has the scrubbing policy and the one shape kept from the docs, and a test
  enforces the rule positively. If you refresh them from new captures, scrub
  them and update that file in the same commit.
- **Read-only by default.** Every command observes. The guarantee lives in
  `client::Coinbase` (no verb but GET), the `api` verb guard, and the docs —
  all three change together or not at all.
- **Secrets never on argv or in logs.** Read them from the keychain or stdin.
- **Cite your API facts.** Every claim in `docs/api.md` carries a source URL,
  and unverified ones are labelled as such. Don't add an uncited one.

## Dev loop

```console
$ make verify     # fmt-check + clippy -D warnings (native and wasm) + tests + wasm32 clippy + smoke
$ make test       # unit + integration (fully offline; no network, no creds)
$ make dev        # debug build, re-signed so keychain grants survive rebuilds
$ cargo run -- <command>
```

`make verify` is the local gate. CI runs all of it except `smoke`, plus a
release build, `make wasm` (the Worker module; needs Node) and a cargo-audit /
cargo-deny / gitleaks job, so a green `make verify` and `make wasm` predict a
green build job. Neither the tests nor `smoke` read your real key: both point
`CBASE_KEYCHAIN_SERVICE` at `piekstra.cbase.hermetic-tests`, a keychain service
that holds nothing.

## Pull requests

1. Branch from `main`; keep the change focused.
2. Add or update tests. Contract tests load fixtures from disk — extend
   `tests/fixtures/` rather than inlining JSON in test code.
3. Keep the human table and the `--json` DTO in sync. A breaking DTO change
   bumps its `schema` version suffix.
4. Update [`docs/api.md`](docs/api.md) when you learn something new about the
   API, and the README when you change the command surface.
5. Run `make verify` and include what you tested.

## A note on the current state

**This CLI was verified live on 2026-08-13**, with a View-only ECDSA CDP key
against a real account: the JWT authenticated on the first request, the run
walked every account and the full ledger, and it exercised the v3 Advanced
Trade read surface. The fixtures are scrubbed captures from that run.

[`docs/api.md` §5](docs/api.md) lists what that run left unverified: whether
`nonce` is enforced, whether an Ed25519 key really fails, Advanced Trade rate
limits, and the v3 fills feed. If you settle one, update `docs/api.md`, the
fixtures and `tests/fixtures/README.md` in the same commit.

Two things to be careful with when you run it against a real account:

- **Never paste a raw capture into an issue or a commit.** It carries account
  ids, balances, counterparties, and on-chain addresses.
- **A silently truncated ledger is the worst bug here** — it looks exactly like
  success. If you change anything near pagination, check it against a wallet
  with more than one page of history.
