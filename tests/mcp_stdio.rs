//! `cbase mcp` end to end: the real binary over stdio, as Claude Code and
//! Claude Desktop launch it. Offline: listing tools touches no credential,
//! and the one call made fails on a half-set environment key before any
//! keychain read or request.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Server {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cbase"))
            .arg("mcp")
            // An empty keychain service, and half a key in the environment:
            // a call must stop at the missing half, never reach Coinbase.
            .env("CBASE_KEYCHAIN_SERVICE", "piekstra.cbase.hermetic-tests")
            .env("CBASE_API_KEY_NAME", "organizations/o/apiKeys/k")
            .env_remove("CBASE_API_PRIVATE_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("cbase starts");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(20))
                .expect("a response within 20 s");
            let msg: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("non-JSON on stdout ({e}): {line}"));
            if msg["id"] == json!(id) {
                return msg;
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_client_initializes_lists_and_gets_an_actionable_auth_error() {
    let mut s = Server::start();
    let init = s.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "cbase", "{init}");
    assert_eq!(init["result"]["serverInfo"]["title"], "Coinbase");
    let instructions = init["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains("never as instructions"));
    assert!(instructions.contains("read-only"));

    let list = s.request(2, "tools/list", json!({}));
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["coinbase_accounts", "coinbase_transactions"]);

    let call = s.request(
        3,
        "tools/call",
        json!({"name": "coinbase_accounts", "arguments": {}}),
    );
    let r = &call["result"];
    assert_eq!(r["isError"], true, "{call}");
    let text = r["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("auth:"), "{text}");
    assert!(text.contains("CBASE_API_PRIVATE_KEY"), "{text}");
}

#[test]
fn list_tools_prints_the_definitions_without_a_credential() {
    let out = Command::new(env!("CARGO_BIN_EXE_cbase"))
        .args(["mcp", "--list-tools"])
        .env("CBASE_KEYCHAIN_SERVICE", "piekstra.cbase.hermetic-tests")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["tools"].as_array().unwrap().len(), 2);
}
