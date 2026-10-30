# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[security advisories](https://github.com/piekstra/coinbase-cli/security/advisories/new)
rather than a public issue.

## Threat model

`cbase` authenticates to Coinbase on behalf of one account holder and reads
their wallet balances and full transaction history. What's worth protecting:

- **The CDP API private key.** Stored in the OS keychain under service
  `piekstra.cbase`, account `api-key`, as the exact JSON file Coinbase issued.
  Read at point of use, parsed in memory, never logged, never on argv, never
  written to disk by this tool. `Credential` implements `Debug` by hand
  precisely so a stray `{:?}` cannot print key material, and the key id is
  masked (`organizations/…/…4f2a`) wherever it is displayed.
- **The minted JWTs.** Held for the duration of a single request, never
  persisted, never logged — `--verbose` prints the method, path, and query
  parameters, never the `Authorization` header. Each token lives 120 seconds and
  is bound to one method+path, so even a leaked one is near-useless.
- **The transaction history itself.** Not a credential, but it is a complete
  financial and counterparty record. It goes to stdout and nowhere else: no
  telemetry, no caching to disk, no third parties.

## Reduce the blast radius: create a View-only key

`cbase` never trades and never transfers. Create the CDP key with the **View**
permission only, and it becomes impossible for this tool — or a bug in it, or
anyone who obtains the key — to move your funds. An IP allowlist in the CDP
portal narrows it further.

## What this tool does not do

- **It never writes.** No orders, no transfers, no key rotation, no profile
  edits. This is enforced in code, not just documented: `client::Coinbase`
  exposes no HTTP verb but `GET`, and the `api` passthrough refuses every other
  verb with exit code 6. There is no code path that can POST.
- It talks only to the configured API host (`api.coinbase.com` by default). The
  `base_url` config key exists for proxies and test servers; if it is set to
  something else, that is where your requests go.
- It hardcodes no secrets and embeds no key material. `gitleaks` runs in CI over
  the full history, and a test refuses any credential-shaped substring in the
  test fixtures.

## Handling the key safely

Pipe it; never paste it as an argument, where it would land in shell history and
in the process table:

```console
$ cbase auth set-credential --stdin < ~/Downloads/cdp_api_key.json
$ rm ~/Downloads/cdp_api_key.json
```

From a password manager:

```console
$ op read 'op://Private/coinbase-cdp/key.json' \
    | cbase auth set-credential --stdin --overwrite
```

Or from the environment, for headless use:

```console
$ CBASE_KEY="$(cat cdp_api_key.json)" cbase auth set-credential --from-env CBASE_KEY
```

`cbase auth logout --forget` removes the key from the keychain and clears the
config. Rotating a key is `auth set-credential --stdin --overwrite`; also revoke
the old one in the CDP portal, since deleting the local copy does not.

## A note on macOS keychain grants

`cargo install` ad-hoc signs the binary, minting a new code identity each time,
and macOS scopes "Always Allow" grants to that identity — so a plain reinstall
silently revokes the grant. `make install` re-signs with the family's stable
identity to avoid this. That is a usability fix, not a security boundary: the
grant still gates keychain access.
