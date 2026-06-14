//! Integration tests for the HTTP MCP endpoint, driven over a real loopback TCP
//! socket with a fake handler. No broker, no children — just the transport: auth
//! and request/response dispatch.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use mcp_lock_core::auth::{StaticBearerValidator, ValidatedClient};
use mcp_lock_transport::endpoint::{HttpEndpoint, McpHandler, Notifier};

/// A handler that echoes the method back, proving the request reached it
/// authenticated.
struct EchoHandler;
impl McpHandler for EchoHandler {
    fn handle(&self, request: &Value, client: &ValidatedClient) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": request.get("id").cloned().unwrap_or(Value::Null),
            "result": {
                "method": request.get("method").and_then(Value::as_str).unwrap_or(""),
                "client": client.client_id(),
            }
        })
    }
}

const TOKEN: &str = "test-bearer-placeholder";

fn start_endpoint() -> std::net::SocketAddr {
    let validator = Arc::new(StaticBearerValidator::new(TOKEN, "claude").unwrap());
    let endpoint = HttpEndpoint::bind(
        "127.0.0.1:0",
        validator,
        Arc::new(EchoHandler),
        Notifier::new(),
    )
    .expect("bind loopback");
    let addr = endpoint.local_addr();
    std::thread::spawn(move || endpoint.run());
    addr
}

/// Minimal raw HTTP/1.1 round-trip; returns (status_code, body).
fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    auth: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let auth_header = match auth {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "{method} / HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        method = method,
        auth = auth_header,
        len = body.len(),
        body = body,
    );
    stream.write_all(request.as_bytes()).unwrap();

    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[test]
fn rejects_request_without_bearer() {
    let addr = start_endpoint();
    let (status, _) = http_request(
        addr,
        "POST",
        None,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
    );
    assert_eq!(status, 401);
}

#[test]
fn rejects_request_with_wrong_bearer() {
    let addr = start_endpoint();
    let (status, _) = http_request(
        addr,
        "POST",
        Some("wrong-token"),
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
    );
    assert_eq!(status, 401);
}

#[test]
fn accepts_authenticated_request_and_dispatches_to_handler() {
    let addr = start_endpoint();
    let (status, body) = http_request(
        addr,
        "POST",
        Some(TOKEN),
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#,
    );
    assert_eq!(status, 200);
    let parsed: Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(parsed["id"], 7);
    assert_eq!(parsed["result"]["method"], "tools/list");
    assert_eq!(parsed["result"]["client"], "claude");
}

#[test]
fn notification_is_accepted_without_body() {
    let addr = start_endpoint();
    // No "id" => notification => 202, no JSON-RPC body.
    let (status, body) = http_request(
        addr,
        "POST",
        Some(TOKEN),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    assert_eq!(status, 202);
    assert!(body.trim().is_empty());
}
