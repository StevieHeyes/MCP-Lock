//! Minimal JSON-RPC 2.0 types for the MCP stdio transport.
//!
//! MCP over stdio is newline-delimited JSON-RPC 2.0: each line is one complete
//! JSON message. We model only what this server needs — requests/notifications
//! inbound, results/errors outbound — and keep `params`/`result` as
//! [`serde_json::Value`] so the protocol surface stays small and explicit.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC error codes used by this server.
pub mod error_codes {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid method parameters.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal server error.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// An inbound JSON-RPC message. A message with no `id` is a notification and
/// receives no response.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Must be `"2.0"`. Captured so we can validate it.
    pub jsonrpc: String,
    /// Request id. Absent for notifications. May be a number or string.
    #[serde(default)]
    pub id: Option<Value>,
    /// Method name.
    pub method: String,
    /// Method parameters, if any.
    #[serde(default)]
    pub params: Option<Value>,
}

impl Request {
    /// Whether this is a notification (no `id`, so no response is owed).
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// An outbound JSON-RPC response (success or error). Exactly one of `result`
/// or `error` is set; `serde` skips the `None` one on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echoes the request id (or `null` if it could not be determined).
    pub id: Value,
    /// Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Present on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    /// Numeric error code (see [`error_codes`]).
    pub code: i64,
    /// Short human-readable message.
    pub message: String,
}

impl Response {
    /// Build a success response for `id` carrying `result`.
    pub fn success(id: Value, result: Value) -> Self {
        Response {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response for `id`.
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Response {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}
