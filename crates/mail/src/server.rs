//! The MCP stdio server loop.
//!
//! MCP over stdio is newline-delimited JSON-RPC 2.0. [`Server::run`] reads one
//! message per line from a reader, dispatches it, and writes one response line
//! per request to a writer. It is generic over the [`MailStore`] and over the
//! reader/writer so the whole loop is driven from tests with an in-memory
//! fixture and string buffers — no stdio, no network.
//!
//! Only stdout carries protocol messages; all diagnostics go to stderr. Mixing
//! anything else into stdout would corrupt the JSON-RPC stream.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::jsonrpc::{error_codes, Request, Response};
use crate::mailstore::MailStore;
use crate::tools;

/// MCP protocol version this server speaks. A baseline that current MCP clients
/// accept; negotiation can be added when a need arises.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// The MCP mail server: a [`MailStore`] plus the metadata it advertises.
#[derive(Debug)]
pub struct Server<S: MailStore> {
    store: S,
    server_name: String,
    server_version: String,
    default_mailbox: String,
}

impl<S: MailStore> Server<S> {
    /// Create a server over `store`, advertising `server_name`/`server_version`
    /// and using `default_mailbox` when a tool call omits one.
    pub fn new(
        store: S,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        default_mailbox: impl Into<String>,
    ) -> Self {
        Server {
            store,
            server_name: server_name.into(),
            server_version: server_version.into(),
            default_mailbox: default_mailbox.into(),
        }
    }

    /// Run the loop until end of input. Reads request lines from `reader` and
    /// writes response lines to `writer`. Blank lines are ignored.
    pub fn run<R: BufRead, W: Write>(&self, reader: R, mut writer: W) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response_line) = self.process_line(&line) {
                writer.write_all(response_line.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    /// Process one input line, returning the serialized response line, or
    /// `None` if the input was a notification (which owes no response).
    pub fn process_line(&self, line: &str) -> Option<String> {
        let response = match serde_json::from_str::<Request>(line) {
            Ok(req) => self.handle_request(req)?,
            Err(_) => {
                // We could not parse the message at all, so we cannot know its
                // id. Reply with a null-id parse error, as JSON-RPC allows.
                Response::error(Value::Null, error_codes::PARSE_ERROR, "invalid JSON")
            }
        };
        // Serializing our own Response cannot fail; fall back defensively.
        Some(serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}"#
                .to_string()
        }))
    }

    /// Dispatch a parsed request. Returns `None` for notifications.
    fn handle_request(&self, req: Request) -> Option<Response> {
        if req.jsonrpc != "2.0" {
            // Honour the no-response-to-notifications rule even when invalid.
            if req.is_notification() {
                return None;
            }
            return Some(Response::error(
                req.id.unwrap_or(Value::Null),
                error_codes::INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ));
        }

        // Notifications: act if relevant, never respond.
        if req.is_notification() {
            return None;
        }

        let id = req.id.clone().unwrap_or(Value::Null);
        let response = match req.method.as_str() {
            "initialize" => Response::success(id, self.initialize_result()),
            "ping" => Response::success(id, json!({})),
            "tools/list" => Response::success(id, json!({ "tools": tools::tool_definitions() })),
            "tools/call" => self.handle_tools_call(id, req.params),
            other => Response::error(
                id,
                error_codes::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            ),
        };
        Some(response)
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version,
            }
        })
    }

    fn handle_tools_call(&self, id: Value, params: Option<Value>) -> Response {
        let Some(params) = params.as_ref().and_then(Value::as_object) else {
            return Response::error(
                id,
                error_codes::INVALID_PARAMS,
                "tools/call requires a params object",
            );
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Response::error(
                id,
                error_codes::INVALID_PARAMS,
                "tools/call requires a string `name`",
            );
        };
        let arguments = params.get("arguments");
        match tools::call(&self.store, name, arguments, &self.default_mailbox) {
            Ok(result) => Response::success(id, result),
            Err(e) => Response::error(id, error_codes::INVALID_PARAMS, e.message),
        }
    }
}
