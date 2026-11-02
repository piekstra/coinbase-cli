//! The Coinbase HTTP client: sign a JWT, send a GET, map the answer onto the
//! family's exit-code contract.
//!
//! Deliberately GET-only. There is no `post`/`put`/`delete` on this type, so
//! "this CLI is read-only" is a property of the code rather than a promise in
//! a README — adding a write means adding a method here, which is a visible
//! change in the same commit as the docs.
//!
//! Each request mints its own token ([`crate::jwt`]): tokens live ~2 minutes
//! and are bound to one method+path, so there is nothing worth caching.
//!
//! Written once against pk-cli-core's [`Transport`], so the terminal binary
//! (`pk_cli_http::BlockingTransport`) and the Cloudflare Worker module
//! (`pk_cli_mcp::wasm::HostTransport`, the Worker's `fetch`) run this same
//! signing, paging and error mapping. Natively the futures finish on their
//! first poll; the commands drive them with `pk_cli_core::block_on`.

use pk_cli_core::transport::{HttpRequest, PlatformSigner, Transport};
use pk_cli_core::CliError;
use serde_json::Value;

use crate::credential::Credential;
use crate::jwt::{self, Signer};

/// Coinbase API paths the reads share.
pub const ACCOUNTS: &str = "/v2/accounts";

/// The transactions path for one account.
pub fn account_transactions(account_id: &str) -> String {
    format!("/v2/accounts/{account_id}/transactions")
}

/// The v2 API is versioned by a `CB-VERSION: YYYY-MM-DD` header. Omit it and
/// Coinbase falls back to whatever version the *key* was created against, so
/// two users running the same binary can get different response shapes.
///
/// This is the literal date from Coinbase's own versioning example, chosen
/// because it is a value they publish rather than one invented here — their
/// guidance is explicitly *"Do not pass in the current date, as that will
/// return the current version which might break your implementation."*
/// <https://docs.cdp.coinbase.com/coinbase-app/api-architecture/versioning>
///
/// Verified live 2026-08-13: the shapes captured in `tests/fixtures/` belong
/// to this pin, so bumping it invalidates them — the pin and the fixtures must
/// move in the same commit. If responses ever disagree with the fixtures, this
/// pin is still the first thing to check.
pub const CB_VERSION: &str = "2022-01-06";

/// Coinbase's documented cap on `?limit=` for v2 list endpoints (range 0–100,
/// default 25). Asking for the maximum minimizes round trips.
pub const MAX_PAGE: u32 = 100;

/// The Coinbase v2 client over any transport: blocking reqwest natively, the
/// Worker's `fetch` and WebCrypto in the module. Signs every request with a
/// fresh CDP JWT, by the transport's platform signer when it has one.
pub struct Coinbase<T> {
    transport: T,
    base_url: String,
    host: String,
    cred: Credential,
    verbose: bool,
    cli_hints: bool,
}

#[cfg(feature = "native")]
impl Coinbase<pk_cli_http::BlockingTransport> {
    /// Build a client from the key in the environment
    /// ([`crate::credential::ENV_KEY_NAME`] + `ENV_PRIVATE_KEY`), else the OS
    /// keychain.
    ///
    /// A missing key is [`CliError::Auth`] (exit 3) with the command that fixes
    /// it, so a driver can branch on the exit code instead of parsing prose.
    pub fn new(
        cfg: &crate::config::Config,
        creds: &pk_cli_secrets::CredentialStore,
        verbose: bool,
    ) -> Result<Self, CliError> {
        let (key, _) = crate::credential::resolve_key(creds)?.ok_or_else(missing_key)?;
        Self::with_key(cfg, &key, verbose)
    }

    /// Build a client from an already-read key blob (the JSON the keychain
    /// holds), so a long-running caller reads the keychain once.
    pub fn with_key(
        cfg: &crate::config::Config,
        key: &pk_cli_secrets::Secret,
        verbose: bool,
    ) -> Result<Self, CliError> {
        let transport = pk_cli_http::BlockingTransport::new()?;
        let mut client =
            Self::with_transport(Credential::parse(key.expose())?, &cfg.base_url(), transport);
        client.verbose = verbose;
        client.cli_hints = true;
        Ok(client)
    }
}

impl<T: Transport + PlatformSigner> Coinbase<T> {
    /// A client over any transport, from a parsed key. Error messages name
    /// no `cbase` command: the Worker builds its client this way, where the
    /// key lives in the Worker's secrets, not a keychain.
    pub fn with_transport(cred: Credential, base_url: &str, transport: T) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let host = host_of(&base_url);
        Self {
            transport,
            base_url,
            host,
            cred,
            verbose: false,
            cli_hints: false,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.cred.key_id
    }

    pub fn masked_key_id(&self) -> String {
        self.cred.masked_key_id()
    }

    pub fn algorithm(&self) -> &'static str {
        self.cred.signer().algorithm()
    }

    /// The signed GET for a path, without sending it, so a test can see
    /// exactly what goes on the wire.
    ///
    /// `path` carries the leading slash and **no** query string: the JWT's
    /// `uri` claim is built from the path alone, so query parameters must
    /// arrive through `query` or the token will not validate.
    pub async fn request(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<HttpRequest, CliError> {
        let token = self.token("GET", path).await?;
        Ok(HttpRequest::get(format!("{}{path}", self.base_url))
            .query(query)
            .header("Authorization", format!("Bearer {token}"))
            .header("CB-VERSION", CB_VERSION)
            .header("Accept", "application/json")
            // On the request, so the binary and the Worker send the same one.
            .user_agent("cbase", env!("CARGO_PKG_VERSION")))
    }

    /// GET a path, with optional query parameters (see [`Self::request`]).
    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, CliError> {
        let req = self.request(path, query).await?;
        if self.verbose {
            // The path and parameters, never the token.
            eprintln!("GET {}{path} {query:?}", self.base_url);
        }
        let resp = self.transport.send(req).await?;
        response_json(resp.status, &resp.body, self.cli_hints)
    }

    /// Mint the per-request JWT. An ES256 signature goes to the transport
    /// first: in the Worker that is WebCrypto, native code well under the
    /// free plan's 10 ms of CPU per request where WebAssembly P-256 is not.
    async fn token(&self, method: &str, path: &str) -> Result<String, CliError> {
        let signer = self.cred.signer();
        let input = jwt::signing_input(
            signer.algorithm(),
            &self.cred.key_id,
            method,
            &self.host,
            path,
            jwt::now_secs(),
            &jwt::nonce(),
        )?;
        // The platform's signer when the transport has one (WebCrypto in the
        // Worker, a fraction of the CPU of signing in WebAssembly); this
        // crate's own when it has none or it refuses the key, which gives
        // the same token.
        let platform = match (signer, self.cred.es256_pkcs8_der()) {
            (Signer::Es256(_), Some(der)) => self.transport.sign_es256(der, input.as_bytes()).await,
            _ => None,
        };
        let signature = match platform {
            Some(Ok(sig)) => sig,
            Some(Err(_)) | None => signer.sign(input.as_bytes()),
        };
        Ok(jwt::assemble(&input, &signature))
    }

    /// Follow a v2 list endpoint's cursor until `limit` records are collected
    /// or the pages run out.
    ///
    /// `limit` is a cap on records, not pages — the caller says "give me 20
    /// transactions" and this decides how many round trips that costs. A page
    /// that returns nothing terminates the walk even if the cursor is still
    /// non-null, so a provider bug cannot spin this forever.
    pub async fn get_all(
        &self,
        path: &str,
        query: &[(&str, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>, CliError> {
        let mut collected: Vec<Value> = Vec::new();
        let mut cursor: Option<String> = None;
        let target = limit.unwrap_or(u32::MAX) as usize;

        loop {
            let mut q: Vec<(&str, String)> = query.to_vec();
            q.push(("limit", MAX_PAGE.to_string()));
            if let Some(c) = &cursor {
                q.push(("starting_after", c.clone()));
            }
            let page = self.get(path, &q).await?;
            let rows = page
                .get("data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let got = rows.len();
            collected.extend(rows);

            if collected.len() >= target || got == 0 {
                break;
            }
            match next_cursor(&page) {
                // A cursor that doesn't advance would page the same records
                // forever. Coinbase shouldn't do that; a walk over someone's
                // whole financial history is not the place to find out.
                Some(c) if Some(&c) != cursor.as_ref() => cursor = Some(c),
                _ => break,
            }
        }
        collected.truncate(target);
        Ok(collected)
    }
}

/// The exit-3 error for "no key anywhere", naming both ways to provide one.
#[cfg(feature = "native")]
pub fn missing_key() -> CliError {
    CliError::Auth(format!(
        "no Coinbase CDP API key stored — create one at https://portal.cdp.coinbase.com and run \
         `cbase auth login --stdin < cdp_api_key.json`, or set {} and {}",
        crate::credential::ENV_KEY_NAME,
        crate::credential::ENV_PRIVATE_KEY
    ))
}

/// The v2 pagination cursor for the next page, or `None` on the last one.
///
/// **`next_uri` is the documented signal, not `next_starting_after`.** Coinbase
/// documents the pagination block as
/// `{ending_before, starting_after, limit, order, previous_uri, next_uri}` and
/// says to stop when `next_uri` is null — `next_starting_after` accompanied it
/// on every page of the 2026-08-13 live capture, but is not part of the
/// published contract. Reading only the latter is a silent-truncation bug the
/// day Coinbase drops it: page one arrives, the field is absent, the walk
/// stops, and a partial ledger is reported as a complete one. So `next_uri` is
/// tried first and the cursor is parsed out of it. (Observed: the live
/// `next_uri` carries no `limit=` — just `?starting_after=<id>`.)
///
/// See `docs/api.md` and
/// <https://docs.cdp.coinbase.com/coinbase-app/api-architecture/pagination>.
pub fn next_cursor(page: &Value) -> Option<String> {
    let pagination = page.get("pagination")?;
    starting_after_of(pagination.get("next_uri").and_then(Value::as_str)).or_else(|| {
        non_empty(
            pagination
                .get("next_starting_after")
                .and_then(Value::as_str),
        )
    })
}

/// Pull `starting_after=<id>` out of a `next_uri` like
/// `/v2/accounts?limit=25&starting_after=abc`.
fn starting_after_of(next_uri: Option<&str>) -> Option<String> {
    let (_, qs) = next_uri?.split_once('?')?;
    qs.split('&')
        .find_map(|pair| pair.strip_prefix("starting_after="))
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.filter(|s| !s.is_empty()).map(String::from)
}

/// Bare host from a base URL, for the JWT `uri` claim.
fn host_of(base_url: &str) -> String {
    base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or("api.coinbase.com")
        .to_string()
}

/// Map a response onto the exit-code contract, preferring Coinbase's own error
/// message over a bare status line.
///
/// Not `pk_cli_http::json_response`, for three reasons:
///
/// 1. That helper maps 403 to the same message as 401. Coinbase answers a key
///    that is merely missing a *scope* with 403, and the fix — re-create the
///    key with the View permission — is different from "your key is bad".
/// 2. It cannot see Coinbase's `errors[]` body, and "HTTP 400 from provider" is
///    a much worse message than the one Coinbase already wrote.
/// 3. **It would call `.json()` on a body that is not always JSON.** Observed
///    2026-08-12: a rejected request to `GET /v2/accounts` answers
///    `content-type: text/plain` with the literal body `Unauthorized` — *not*
///    the documented JSON error shape. Parsing that as JSON yields a confusing
///    deserialization error instead of "your key was rejected". So the body is
///    read as text first and JSON is only attempted opportunistically.
///
/// `cli_hints` adds the `cbase` command that checks the key to a 401; the
/// Worker leaves it out, where no terminal is involved.
pub fn response_json(status: u16, body: &str, cli_hints: bool) -> Result<Value, CliError> {
    let parsed: Option<Value> = serde_json::from_str(body).ok();

    if (200..300).contains(&status) {
        return parsed.ok_or_else(|| {
            CliError::Upstream(format!(
                "Coinbase returned HTTP {status} with a non-JSON body"
            ))
        });
    }

    let detail = parsed.as_ref().and_then(error_message);
    let say = |fallback: &str| match &detail {
        Some(m) => format!("{m} (HTTP {status})"),
        None => format!("{fallback} (HTTP {status})"),
    };

    Err(match status {
        401 if cli_hints => CliError::Auth(say(
            "Coinbase rejected the API key — check it with `cbase auth status --verify`",
        )),
        401 => CliError::Auth(say("Coinbase rejected the API key")),
        403 => CliError::Auth(say(
            "Coinbase refused the request; the API key is probably missing the read permission \
             for this resource",
        )),
        404 => CliError::NotFound(say("no such Coinbase resource")),
        429 => CliError::Upstream(say("Coinbase rate limit exceeded — retry shortly")),
        _ => CliError::Upstream(say("Coinbase returned an error")),
    })
}

/// Coinbase speaks two error dialects. v2 (`/v2/...`) answers
/// `{"errors":[{"id":"...","message":"..."}]}`; v3 Advanced Trade answers
/// `{"error":"...","message":"...","error_details":"..."}`. Read whichever is
/// present rather than assuming the endpoint's family.
fn error_message(body: &Value) -> Option<String> {
    v2_error_message(body).or_else(|| v3_error_message(body))
}

fn v2_error_message(body: &Value) -> Option<String> {
    let first = body.get("errors")?.as_array()?.first()?;
    let msg = first.get("message").and_then(Value::as_str);
    let id = first.get("id").and_then(Value::as_str);
    match (id, msg) {
        (Some(i), Some(m)) => Some(format!("{m} [{i}]")),
        (_, Some(m)) => Some(m.to_string()),
        (Some(i), _) => Some(i.to_string()),
        _ => None,
    }
}

/// The v3 dialect, checked second so a v2 body wins when both somehow appear.
fn v3_error_message(body: &Value) -> Option<String> {
    let msg = body
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| body.get("error_details").and_then(Value::as_str))
        .or_else(|| body.get("error").and_then(Value::as_str))?;
    Some(msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn transaction_paths_are_scoped_to_the_account() {
        assert_eq!(
            account_transactions("abc-123"),
            "/v2/accounts/abc-123/transactions"
        );
    }

    #[test]
    fn a_rejected_key_names_the_cli_check_only_for_the_cli() {
        let msg = |hints| match response_json(401, "Unauthorized", hints) {
            Err(CliError::Auth(m)) => m,
            other => panic!("{other:?}"),
        };
        assert!(msg(true).contains("`cbase auth status --verify`"));
        assert_eq!(msg(false), "Coinbase rejected the API key (HTTP 401)");
        assert!(matches!(
            response_json(200, "not json", false),
            Err(CliError::Upstream(_))
        ));
        assert_eq!(
            response_json(200, r#"{"data":[]}"#, false).unwrap(),
            json!({"data": []})
        );
    }

    #[test]
    fn host_is_stripped_of_scheme_and_path() {
        assert_eq!(host_of("https://api.coinbase.com"), "api.coinbase.com");
        assert_eq!(host_of("https://api.coinbase.com/"), "api.coinbase.com");
        assert_eq!(host_of("http://localhost:8080/x"), "localhost:8080");
    }

    #[test]
    fn v2_error_bodies_are_read_for_their_message() {
        let body = json!({"errors":[{"id":"invalid_token","message":"invalid api key"}]});
        assert_eq!(
            error_message(&body).as_deref(),
            Some("invalid api key [invalid_token]")
        );
    }

    /// Observed live on 2026-08-12: Coinbase answers a rejected request with
    /// `text/plain` `Unauthorized`, not the documented JSON error object. The
    /// message readers must return `None` for it rather than panicking or
    /// inventing a message, so the caller's own fallback text is used.
    #[test]
    fn the_plain_text_unauthorized_body_is_not_mistaken_for_json() {
        assert!(serde_json::from_str::<Value>("Unauthorized").is_err());
        // And a JSON scalar, should Coinbase ever send one, still yields nothing.
        assert!(error_message(&json!("Unauthorized")).is_none());
    }

    #[test]
    fn v3_error_bodies_are_read_too() {
        let body = json!({"error":"PERMISSION_DENIED","message":"missing scope"});
        assert_eq!(v3_error_message(&body).as_deref(), Some("missing scope"));
    }

    #[test]
    fn a_body_with_no_error_fields_yields_nothing_rather_than_a_panic() {
        assert!(error_message(&json!({})).is_none());
        assert!(error_message(&json!({"errors":[]})).is_none());
        assert!(v3_error_message(&json!({})).is_none());
        // Wrong types where objects/arrays are expected must not panic either.
        assert!(error_message(&json!({"errors": "boom"})).is_none());
        assert!(error_message(&json!([1, 2, 3])).is_none());
    }

    /// The dialects must not shadow each other: a v2 body still reads as v2
    /// even though `error_message` falls through to the v3 reader.
    #[test]
    fn the_v2_dialect_wins_when_both_shapes_are_present() {
        let body = json!({
            "errors": [{"id":"not_found","message":"account not found"}],
            "message": "something else",
        });
        assert_eq!(
            error_message(&body).as_deref(),
            Some("account not found [not_found]")
        );
    }

    /// The documented shape: the cursor lives inside `next_uri`. Getting this
    /// wrong truncates a ledger silently, which is the worst way to be wrong
    /// about a tax record.
    #[test]
    fn the_cursor_is_parsed_out_of_the_documented_next_uri() {
        let page = json!({"pagination": {
            "ending_before": null,
            "starting_after": null,
            "limit": 25,
            "order": "desc",
            "previous_uri": null,
            "next_uri": "/v2/accounts?limit=25&starting_after=abc",
        }});
        assert_eq!(next_cursor(&page).as_deref(), Some("abc"));
    }

    #[test]
    fn a_null_next_uri_is_the_last_page() {
        let page = json!({"pagination": {"limit": 25, "order": "desc", "next_uri": null}});
        assert!(next_cursor(&page).is_none());
        assert!(next_cursor(&json!({"pagination": {}})).is_none());
        assert!(next_cursor(&json!({"data": []})).is_none());
    }

    /// `next_starting_after` is not in the published contract but shows up on
    /// some responses — honoured as a fallback so a page that has it still
    /// pages correctly.
    #[test]
    fn the_undocumented_cursor_field_still_works_as_a_fallback() {
        let page = json!({"pagination": {"next_uri": null, "next_starting_after": "xyz"}});
        assert_eq!(next_cursor(&page).as_deref(), Some("xyz"));
        assert!(next_cursor(&json!({"pagination":{"next_starting_after":""}})).is_none());
    }

    #[test]
    fn a_next_uri_without_a_cursor_does_not_loop_forever() {
        // No query string, and a query string with other parameters only:
        // both must read as "no next page" rather than yielding a bogus cursor.
        assert!(next_cursor(&json!({"pagination":{"next_uri":"/v2/accounts"}})).is_none());
        assert!(next_cursor(&json!({"pagination":{"next_uri":"/v2/accounts?limit=25"}})).is_none());
    }
}
