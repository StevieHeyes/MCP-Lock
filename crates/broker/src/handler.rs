//! The broker's [`McpHandler`]: it answers MCP requests from the upstream client
//! by consulting the aggregator (and thus the security-core exposure gate).
//!
//! The aggregator is behind a `Mutex` because the HTTP endpoint handles requests
//! on multiple threads; access is serialized, which is fine for v1's volume and
//! keeps the child stdio interaction simple.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};

use mcp_lock_core::auth::ValidatedClient;
use mcp_lock_core::policy::Timestamp;
use mcp_lock_transport::endpoint::McpHandler;

use crate::aggregator::{Aggregator, AggregatorError};

/// MCP protocol version the broker presents upward.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// An [`McpHandler`] backed by the broker's aggregator.
pub struct BrokerMcpHandler {
    aggregator: Arc<Mutex<Aggregator>>,
    /// Monotonic base; `now()` is seconds since the handler was created. Used for
    /// elevation-expiry checks in exposure resolution (no elevations exist until
    /// Slice 5, but the clock is consistent from the start).
    clock_base: Instant,
}

impl std::fmt::Debug for BrokerMcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerMcpHandler").finish()
    }
}

impl BrokerMcpHandler {
    /// Wrap a shared aggregator.
    pub fn new(aggregator: Arc<Mutex<Aggregator>>) -> Self {
        BrokerMcpHandler {
            aggregator,
            clock_base: Instant::now(),
        }
    }

    fn now(&self) -> Timestamp {
        self.clock_base.elapsed().as_secs()
    }

    fn handle_tools_list(&self, id: Value) -> Value {
        let now = self.now();
        match self.aggregator.lock() {
            Ok(agg) => success(id, json!({ "tools": agg.aggregated_tools(now) })),
            Err(_) => internal_error(id),
        }
    }

    fn handle_tools_call(&self, id: Value, params: Option<&Value>) -> Value {
        let Some(params) = params.and_then(Value::as_object) else {
            return error(id, -32602, "tools/call requires a params object");
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return error(id, -32602, "tools/call requires a string `name`");
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let now = self.now();

        let mut agg = match self.aggregator.lock() {
            Ok(agg) => agg,
            Err(_) => return internal_error(id),
        };
        match agg.call(name, arguments, now) {
            Ok(result) => success(id, result),
            // Tool-level problems are returned as a tool result with isError so
            // the model can see and adjust, not as a JSON-RPC protocol error.
            Err(e @ (AggregatorError::UnknownTool(_) | AggregatorError::NotExposed(_))) => {
                success(id, tool_error_result(&e.to_string()))
            }
            Err(AggregatorError::Child(e)) => success(id, tool_error_result(&e.to_string())),
            Err(e @ AggregatorError::InvalidServerId(_)) => {
                // Should not occur after a successful build; surface defensively.
                success(id, tool_error_result(&e.to_string()))
            }
        }
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": true } },
            "serverInfo": { "name": "mcp-lockd", "version": env!("CARGO_PKG_VERSION") }
        })
    }
}

impl McpHandler for BrokerMcpHandler {
    fn handle(&self, request: &Value, _client: &ValidatedClient) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        match method {
            "initialize" => success(id, self.initialize_result()),
            "ping" => success(id, json!({})),
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tools_call(id, request.get("params")),
            other => error(id, -32601, format!("method not found: {other}")),
        }
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

fn internal_error(id: Value) -> Value {
    error(id, -32603, "internal error")
}

fn tool_error_result(message: &str) -> Value {
    json!({ "content": [ { "type": "text", "text": message } ], "isError": true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_lock_core::manifest::load_from_bytes;
    use mcp_lock_core::policy::Elevation;

    use crate::mcp_client::{ChildError, McpChild, ToolDef};

    struct FakeChild;
    impl McpChild for FakeChild {
        fn list_tools(&mut self) -> Result<Vec<ToolDef>, ChildError> {
            Ok(vec![
                ToolDef {
                    name: "search".to_string(),
                    definition: json!({"name":"search"}),
                },
                ToolDef {
                    name: "delete_message".to_string(),
                    definition: json!({"name":"delete_message"}),
                },
            ])
        }
        fn call_tool(&mut self, name: &str, _args: Value) -> Result<Value, ChildError> {
            Ok(json!({"content":[{"type":"text","text":format!("ran {name}")}],"isError":false}))
        }
    }

    const MANIFEST: &[u8] = br#"{"servers":[{"id":"mail","command":"x","tools":{"search":"read","delete_message":"write"}}]}"#;

    fn handler() -> BrokerMcpHandler {
        let loaded = load_from_bytes(MANIFEST).unwrap();
        let agg =
            Aggregator::build(&loaded, |_| Ok(Box::new(FakeChild) as Box<dyn McpChild>)).unwrap();
        BrokerMcpHandler::new(Arc::new(Mutex::new(agg)))
    }

    fn fake_client() -> ValidatedClient {
        // Build a ValidatedClient via the real validator (the only way).
        use mcp_lock_core::auth::{CredentialValidator, StaticBearerValidator};
        StaticBearerValidator::new("t", "c")
            .unwrap()
            .validate(Some("t"))
            .unwrap()
    }

    #[test]
    fn initialize_advertises_list_changed() {
        let h = handler();
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            &fake_client(),
        );
        assert_eq!(resp["result"]["capabilities"]["tools"]["listChanged"], true);
    }

    #[test]
    fn tools_list_is_read_only_then_changes_after_elevation() {
        let h = handler();
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &fake_client(),
        );
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["mail.search"]); // delete_message gated out

        h.aggregator
            .lock()
            .unwrap()
            .state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::until_revoked(0));
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            &fake_client(),
        );
        assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn call_to_gated_tool_is_a_tool_error_not_protocol_error() {
        let h = handler();
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mail.delete_message","arguments":{}}}),
            &fake_client(),
        );
        assert!(resp["error"].is_null());
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn exposed_call_routes_to_child() {
        let h = handler();
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mail.search","arguments":{"query":"x"}}}),
            &fake_client(),
        );
        assert_eq!(resp["result"]["isError"], false);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("ran search"));
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let h = handler();
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"nope"}),
            &fake_client(),
        );
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn malformed_tools_call_is_invalid_params() {
        let h = handler();
        let resp = h.handle(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}),
            &fake_client(),
        );
        assert_eq!(resp["error"]["code"], -32602);
    }
}
