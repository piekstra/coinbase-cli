# CLAUDE.md

The canonical agent guide is [AGENTS.md](AGENTS.md) — read it first. It has the
layout, the auth model, the conventions, and Coinbase's traps.

Claude-specific notes:

- **`make verify` is the gate.** Run it before calling a change done. It runs
  `fmt-check`, `clippy -D warnings` (with and without `wasm`), the tests,
  wasm32 clippy and `smoke`. CI runs all of that except `smoke`, plus a
  release build, `make wasm` and an audit / deny / gitleaks job. `smoke` reads
  only the empty `piekstra.cbase.hermetic-tests` keychain service, never the
  real key (AGENTS.md, "Dev loop").
- **Live verification happened on 2026-08-13.** A View-only ECDSA CDP key
  proved the hand-rolled JWT, walked all 130 accounts and a 3,559-row ledger,
  and exercised the v3 Advanced Trade read surface. The fixtures are scrubbed
  captures from that run (`tests/fixtures/README.md`). `docs/api.md` §5 lists
  what it left unverified: nonce enforcement, Ed25519 rejection, Advanced Trade
  rate limits and the v3 fills feed. Don't write "verified" or "confirmed
  working" about anything you didn't actually run.
- **Tests are offline.** No test may touch the network, the keychain, or a
  credential. If you need new Coinbase data, add a fixture and cite the doc URL
  in `tests/fixtures/README.md`.
- **This CLI is read-only, enforced in three places that must agree:**
  `client::Coinbase` (no verb but GET), the `api` verb guard, and the claims in
  `README.md`/`AGENTS.md`. Change one, change all three.
- **Never commit key material.** Not even a throwaway PEM. Tests generate keys
  at runtime; there must never be a `.pem` in the tree.
- **Don't invent API facts.** Every claim in `docs/api.md` carries a source URL,
  and the unverified ones are labelled. Keep it that way — if you learn
  something new, cite it; if you can't, mark it unconfirmed.
- **A silently truncated ledger is the worst bug this tool can have.** It looks
  like success. The pagination logic and its tests exist for that reason; treat
  changes there with suspicion.
