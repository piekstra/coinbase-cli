# CLAUDE.md

The canonical agent guide is [AGENTS.md](AGENTS.md) — read it first. It has the
layout, the auth model, the conventions, and Coinbase's traps.

Claude-specific notes:

- **`make verify` is the gate.** Run it before calling a change done; it's
  exactly what CI runs (`fmt-check` + `clippy -D warnings` + tests + smoke).
- **This CLI has never made an authenticated Coinbase call** and has never read
  account data. Don't write "verified" or "confirmed working" about anything
  touching the network. The fixtures are hand-authored from published docs, not
  captures — `tests/fixtures/README.md` is explicit about what that does and
  doesn't prove. Reaching a 401 proves the transport, not the JWT.
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
