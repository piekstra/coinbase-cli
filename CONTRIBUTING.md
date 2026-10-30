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
- **Fixtures are hand-authored from published docs, with dummy values only.**
  See [`tests/fixtures/README.md`](tests/fixtures/README.md); a test enforces
  the rule positively. If you ever replace them with real captures, scrub them
  and say so there.
- **Read-only by default.** Every command observes. The guarantee lives in
  `client::Coinbase` (no verb but GET), the `api` verb guard, and the docs —
  all three change together or not at all.
- **Secrets never on argv or in logs.** Read them from the keychain or stdin.
- **Cite your API facts.** Every claim in `docs/api.md` carries a source URL,
  and unverified ones are labelled as such. Don't add an uncited one.

## Dev loop

```console
$ make verify     # fmt-check + clippy -D warnings + tests + smoke — the CI gate
$ make test       # unit + integration (fully offline; no network, no creds)
$ make dev        # debug build, re-signed so keychain grants survive rebuilds
$ cargo run -- <command>
```

`make verify` is exactly what CI runs; a green local run predicts a green CI run.

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

**This CLI has never made a live Coinbase API call.** It was built offline from
published documentation, and its fixtures are hand-authored rather than
captured. That is unusual for this family and is called out in
`tests/fixtures/README.md`.

If you are the first person to run it against a real account: please work
through the checklist in [`docs/api.md` §5](docs/api.md), and turn whatever you
find into fixtures and doc corrections. Expect to find something — a stale
`CB-VERSION` pin, a renamed field, a shape the docs don't quite match. That
first run is the most valuable contribution this repo can receive right now.

Two things to be careful with when you do:

- **Never paste a raw capture into an issue or a commit.** It carries account
  ids, balances, counterparties, and on-chain addresses.
- **A silently truncated ledger is the worst bug here** — it looks exactly like
  success. If you change anything near pagination, check it against a wallet
  with more than one page of history.
