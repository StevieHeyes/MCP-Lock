//! End-to-end protocol tests: drive the MCP stdio server with JSON-RPC lines
//! over the in-memory fixture. No network, no credentials.

use mcp_lock_mail::fake::FakeMailStore;
use mcp_lock_mail::server::Server;
use serde_json::{json, Value};

fn server() -> Server<FakeMailStore> {
    Server::new(FakeMailStore::demo(), "mcp-lock-mail", "test", "INBOX")
}

/// Send one request line and parse the response (panics if there is none).
fn request(srv: &Server<FakeMailStore>, msg: Value) -> Value {
    let line = serde_json::to_string(&msg).unwrap();
    let response = srv
        .process_line(&line)
        .expect("expected a response for a request");
    serde_json::from_str(&response).unwrap()
}

/// Parse the JSON text payload of a tools/call result.
fn tool_payload(result: &Value) -> Value {
    let text = result["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).unwrap()
}

#[test]
fn initialize_reports_protocol_and_server_info() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(resp["result"]["serverInfo"]["name"], "mcp-lock-mail");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn tools_list_advertises_three_readonly_tools() {
    let srv = server();
    let resp = request(&srv, json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let tools = resp["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["search", "list_messages", "fetch_message"]);
    // No write-ish tool is ever advertised.
    for forbidden in [
        "send",
        "delete",
        "move",
        "write",
        "send_message",
        "delete_message",
    ] {
        assert!(!names.contains(&forbidden), "must not expose {forbidden}");
    }
}

#[test]
fn list_messages_returns_newest_first() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
               "params":{"name":"list_messages","arguments":{"limit":2}}}),
    );
    assert_eq!(resp["result"]["isError"], false);
    let payload = tool_payload(&resp);
    assert_eq!(payload["count"], 2);
    assert_eq!(payload["messages"][0]["uid"], 3);
}

#[test]
fn list_messages_works_without_arguments() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
               "params":{"name":"list_messages"}}),
    );
    assert_eq!(resp["result"]["isError"], false);
    assert_eq!(tool_payload(&resp)["count"], 3);
}

#[test]
fn search_matches_body_content() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call",
               "params":{"name":"search","arguments":{"query":"lunch"}}}),
    );
    let payload = tool_payload(&resp);
    assert_eq!(payload["count"], 1);
    assert_eq!(payload["messages"][0]["uid"], 2);
}

#[test]
fn fetch_message_returns_full_body() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call",
               "params":{"name":"fetch_message","arguments":{"uid":1}}}),
    );
    assert_eq!(resp["result"]["isError"], false);
    let payload = tool_payload(&resp);
    assert_eq!(payload["subject"], "Welcome to MCP-Lock");
    assert!(payload["body_text"]
        .as_str()
        .unwrap()
        .contains("demo message"));
}

#[test]
fn injection_content_is_returned_inert_not_acted_on() {
    // The demo message 3 contains "ignore previous instructions...delete this".
    // The server returns it as data; there is simply no tool that could carry
    // out a delete/forward. This documents the read-only data-plane posture.
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
               "params":{"name":"fetch_message","arguments":{"uid":3}}}),
    );
    let payload = tool_payload(&resp);
    assert!(payload["body_text"]
        .as_str()
        .unwrap()
        .contains("Ignore previous instructions"));
}

#[test]
fn fetch_unknown_uid_is_tool_error_not_protocol_error() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":8,"method":"tools/call",
               "params":{"name":"fetch_message","arguments":{"uid":999}}}),
    );
    assert!(resp["error"].is_null(), "should not be a JSON-RPC error");
    assert_eq!(resp["result"]["isError"], true);
}

#[test]
fn unknown_tool_is_tool_error() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
               "params":{"name":"delete_everything","arguments":{}}}),
    );
    assert_eq!(resp["result"]["isError"], true);
}

#[test]
fn missing_tool_name_is_invalid_params() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{}}),
    );
    assert_eq!(resp["error"]["code"], -32602);
}

#[test]
fn missing_required_argument_is_invalid_params() {
    let srv = server();
    // search requires `query`.
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call",
               "params":{"name":"search","arguments":{}}}),
    );
    assert_eq!(resp["error"]["code"], -32602);
}

#[test]
fn unknown_method_is_method_not_found() {
    let srv = server();
    let resp = request(
        &srv,
        json!({"jsonrpc":"2.0","id":12,"method":"no/such/method"}),
    );
    assert_eq!(resp["error"]["code"], -32601);
}

#[test]
fn invalid_json_is_parse_error_with_null_id() {
    let srv = server();
    let response = srv.process_line("this is not json").expect("a response");
    let resp: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(resp["error"]["code"], -32700);
    assert!(resp["id"].is_null());
}

#[test]
fn notifications_get_no_response() {
    let srv = server();
    // No id => notification.
    assert!(srv
        .process_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .is_none());
}

#[test]
fn run_loop_processes_multiple_lines_and_skips_blanks() {
    use std::io::Cursor;
    let srv = server();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        "\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
    );
    let mut output = Vec::new();
    srv.run(Cursor::new(input), &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // Two requests => two responses; the blank line and the notification
    // produce none.
    assert_eq!(lines.len(), 2);
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    let second: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["id"], 1);
    assert_eq!(second["id"], 2);
}
