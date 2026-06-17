//! Integration test: the broker supervises the *real* Slice 1 mail server as a
//! child process (broker as parent) and aggregates its tools — no rewrite of the
//! mail server. Uses the mail server's `--fake` mode, so no network or
//! credentials are involved.
//!
//! The mail binary is built as part of `cargo test --workspace`; this test
//! locates it next to the test runner. If it is not present (e.g. when running
//! only `-p mcp-lockd`), the test degrades to a no-op with a notice rather than
//! failing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use mcp_lock_core::exec::ExecutionContext;
use mcp_lock_core::manifest::load_from_bytes;
use mcp_lockd::aggregator::Aggregator;
use mcp_lockd::mcp_client::{McpChild, StdioMcpClient};
use serde_json::json;

/// Locate the `mcp-lock-mail` binary next to this test runner (target/<profile>/).
fn mail_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // exe: target/<profile>/deps/real_child-<hash>
    let deps = exe.parent()?;
    let profile_dir = deps.parent()?;
    let candidate = profile_dir.join("mcp-lock-mail");
    candidate.exists().then_some(candidate)
}

#[test]
fn broker_supervises_real_mail_server_and_aggregates_tools() {
    let Some(bin) = mail_binary() else {
        eprintln!("skipping: mcp-lock-mail binary not found (run via `cargo test --workspace`)");
        return;
    };
    let bin = bin.to_string_lossy().to_string();

    // A manifest that adopts the real mail server in --fake mode, read-only.
    let manifest = format!(
        r#"{{
            "servers": [{{
                "id": "mail",
                "command": "{}",
                "args": ["--fake"],
                "tools": {{
                    "search": "read",
                    "list_messages": "read",
                    "fetch_message": "read"
                }}
            }}]
        }}"#,
        bin.replace('\\', "\\\\")
    );
    let loaded = load_from_bytes(manifest.as_bytes()).unwrap();

    let mut agg = Aggregator::build(&loaded, |server| {
        let ctx = ExecutionContext::first_party(Vec::new());
        let env: BTreeMap<String, String> = server.env.clone();
        StdioMcpClient::spawn(&server.command, &server.args, &ctx, &env)
            .map(|c| Box::new(c) as Box<dyn McpChild>)
    })
    .expect("aggregator should build by spawning the real mail server");

    // Aggregated, namespaced, read-only tools.
    let tools = agg.aggregated_tools(0);
    let mut names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["mail.fetch_message", "mail.list_messages", "mail.search"]
    );

    // Route a real call through the broker to the child and back.
    let result = agg
        .call("mail.fetch_message", json!({ "uid": 1 }), 0)
        .expect("fetch_message should route to the child");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("Welcome to MCP-Lock"),
        "expected the demo message body, got: {text}"
    );

    // A search routes too.
    let search = agg
        .call("mail.search", json!({ "query": "lunch" }), 0)
        .expect("search should route to the child");
    assert_eq!(search["isError"], false);
}
