//! `cbase api <METHOD> <PATH>` — raw passthrough to any Coinbase API endpoint.
//!
//! The escape hatch for surfaces the typed commands don't cover, and the
//! quickest way to check whether a response shape has drifted. The JWT is
//! minted and attached automatically.
//!
//! **GET only.** Coinbase's API can place orders, move funds off-platform, and
//! rotate keys; every one of those is a POST/PUT/DELETE. Rejecting the verbs
//! outright is what makes "read-only" a property of this binary rather than a
//! claim in its README — and it means the escape hatch cannot become the hole
//! in the guarantee. Exit 6 (confirmation required), not 2, so a caller can
//! tell "this tool won't do that" from "you typed it wrong".

use pk_cli_core::{output, CliError};
use pk_cli_http::ApiArgs;

use super::Ctx;

pub fn run(ctx: &Ctx, args: &ApiArgs) -> Result<(), CliError> {
    // Validate the whole invocation before the keychain or the network.
    let method = args.method.trim().to_uppercase();
    if method != "GET" {
        return Err(CliError::ConfirmationRequired(format!(
            "{method} is a write verb and cbase is read-only — only GET is allowed through \
             `cbase api`"
        )));
    }
    if args.data.is_some() {
        return Err(CliError::Usage(
            "--data has no meaning for a GET; cbase api is read-only".into(),
        ));
    }
    let (path, query) = split_query(&args.path)?;

    let payload = ctx.client()?.get(&path, &query)?;
    output::json(&payload);
    Ok(())
}

/// A path and its decomposed query parameters, ready for the client's `get`.
type PathAndQuery<'a> = (String, Vec<(&'a str, String)>);

/// Split `/v2/accounts?limit=10` into the path and its parameters.
///
/// They have to travel separately: the JWT's `uri` claim is built from the path
/// alone, so a query string left glued to the path produces a token Coinbase
/// rejects — a 401 that looks like a bad key and isn't.
fn split_query(raw: &str) -> Result<PathAndQuery<'_>, CliError> {
    let raw = raw.trim();
    if !raw.starts_with('/') {
        return Err(CliError::Usage(format!(
            "path must start with `/` (e.g. /v2/accounts), got `{raw}`"
        )));
    }
    let (path, qs) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw, ""),
    };
    let query = qs
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k, v.to_string()),
            None => (pair, String::new()),
        })
        .collect();
    Ok((path.to_string(), query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_string_is_split_off_the_path() {
        let (path, q) = split_query("/v2/accounts?limit=10&starting_after=abc").unwrap();
        assert_eq!(path, "/v2/accounts");
        assert_eq!(
            q,
            vec![
                ("limit", "10".to_string()),
                ("starting_after", "abc".into())
            ]
        );
    }

    #[test]
    fn a_bare_path_has_no_parameters() {
        let (path, q) = split_query("/v2/accounts").unwrap();
        assert_eq!(path, "/v2/accounts");
        assert!(q.is_empty());
    }

    #[test]
    fn a_path_without_a_leading_slash_is_a_usage_error() {
        assert!(matches!(
            split_query("v2/accounts"),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            split_query("https://api.coinbase.com/v2/accounts"),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn a_valueless_parameter_does_not_panic() {
        let (_, q) = split_query("/v2/accounts?flag&limit=1").unwrap();
        assert_eq!(q[0], ("flag", String::new()));
    }
}
