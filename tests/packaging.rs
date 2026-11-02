//! The Claude Desktop extension manifest (`packaging/mcpb/manifest.json`)
//! against the code it packages, so a release cannot ship a manifest that
//! names a tool, a version or an environment variable the binary does not
//! have. The release workflow validates the schema with the `mcpb` CLI.

use cbase::credential::{ENV_KEY_NAME, ENV_PRIVATE_KEY};
use cbase::mcp::{CoinbaseTools, Source};
use pk_cli_core::CliError;
use pk_cli_mcp::Toolset;
use serde_json::Value;

fn manifest() -> Value {
    let path = format!(
        "{}/packaging/mcpb/manifest.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct NoSource;

impl Source for NoSource {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        unreachable!()
    }
    async fn transactions(&self, _: &str, _: Option<u32>) -> Result<Vec<Value>, CliError> {
        unreachable!()
    }
}

#[test]
fn the_manifest_version_is_the_crate_version() {
    assert_eq!(manifest()["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn the_manifest_lists_exactly_the_served_tools() {
    let listed: Vec<String> = manifest()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    let served: Vec<String> = CoinbaseTools::new(NoSource, None)
        .tools()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(listed, served);
}

#[test]
fn every_platform_runs_mcp_with_the_key_from_sensitive_settings() {
    let m = manifest();
    let config = &m["server"]["mcp_config"];
    let mut configs = vec![config.clone()];
    for os in ["win32", "linux"] {
        configs.push(config["platform_overrides"][os].clone());
    }
    for c in &configs {
        assert_eq!(c["args"], serde_json::json!(["mcp"]), "{c}");
        assert!(
            c["command"]
                .as_str()
                .unwrap()
                .starts_with("${__dirname}/server/"),
            "{c}"
        );
        let env = c["env"].as_object().unwrap();
        assert_eq!(env.len(), 2, "{c}");
        assert_eq!(env[ENV_KEY_NAME], "${user_config.api_key_name}");
        assert_eq!(env[ENV_PRIVATE_KEY], "${user_config.api_private_key}");
    }
    for key in ["api_key_name", "api_private_key"] {
        let setting = &m["user_config"][key];
        assert_eq!(setting["sensitive"], true, "{key}");
        assert_eq!(setting["required"], true, "{key}");
    }
}
