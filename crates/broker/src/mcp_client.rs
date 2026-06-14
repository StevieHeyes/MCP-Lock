//! Synchronous stdio MCP client for child servers.
//!
//! The broker spawns each MCP server as a child process and speaks
//! newline-delimited JSON-RPC 2.0 to it over the child's stdin/stdout. Because
//! the broker is the parent, it owns the child's lifecycle. Calls are serialized
//! per child (one request, read until the matching response), which is all the
//! aggregator needs and keeps the client simple and synchronous.
//!
//! The [`McpChild`] trait is the seam the aggregator depends on, so it can be
//! driven by an in-process fake in tests without spawning anything.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

use mcp_lock_core::exec::ExecutionContext;

/// MCP protocol version the broker speaks to children.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// A tool a child advertises: its name plus the full MCP tool definition
/// (description, inputSchema) to pass through to the upstream client.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// The tool name as the child advertises it (un-namespaced).
    pub name: String,
    /// The full tool definition object from the child's `tools/list`.
    pub definition: Value,
}

/// Errors talking to a child server.
#[derive(Debug)]
pub enum ChildError {
    /// An IO error on the pipe or process.
    Io(std::io::Error),
    /// A protocol violation (unparseable message, missing field).
    Protocol(String),
    /// The child returned a JSON-RPC error.
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// Error message from the child.
        message: String,
    },
    /// The child closed its output / exited.
    Exited,
}

impl fmt::Display for ChildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChildError::Io(e) => write!(f, "child io error: {e}"),
            ChildError::Protocol(m) => write!(f, "child protocol error: {m}"),
            ChildError::Rpc { code, message } => {
                write!(f, "child returned error {code}: {message}")
            }
            ChildError::Exited => write!(f, "child exited"),
        }
    }
}

impl std::error::Error for ChildError {}

/// The seam the aggregator depends on: something it can list tools from and call
/// tools on. Implemented by [`StdioMcpClient`] (a real child) and by test fakes.
pub trait McpChild: Send {
    /// List the tools the child currently advertises.
    fn list_tools(&mut self) -> Result<Vec<ToolDef>, ChildError>;

    /// Invoke a tool on the child by its (un-namespaced) name.
    fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, ChildError>;
}

/// A child MCP server spoken to over stdio. The broker is its parent.
#[derive(Debug)]
pub struct StdioMcpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl StdioMcpClient {
    /// Spawn `command` with `args` and `env`, perform the MCP `initialize`
    /// handshake, and return a ready client.
    ///
    /// `ctx` is the execution context the child runs under. In v1 it is always
    /// first-party with no sandbox; v2 attaches per-child isolation and scoped
    /// credentials here (via `ProcessIsolator` / `SecureKeyStore`) without
    /// changing this call. `env` carries only non-secret config from the
    /// manifest; secret injection is a Slice 5 concern.
    pub fn spawn(
        command: &str,
        args: &[String],
        ctx: &ExecutionContext,
        env: &BTreeMap<String, String>,
    ) -> Result<Self, ChildError> {
        // v1 posture: first-party, broker identity, no sandbox. The context is
        // accepted now so the spawn signature does not change when v2 slots in
        // isolation/scoped-credentials behind it.
        debug_assert!(!ctx.is_sandboxed(), "v1 spawns first-party, unsandboxed");

        let mut command_builder = Command::new(command);
        command_builder
            .args(args)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Let the child's diagnostics flow to the broker's stderr; only its
            // stdout is the protocol channel.
            .stderr(Stdio::inherit());

        let mut child = command_builder.spawn().map_err(ChildError::Io)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ChildError::Protocol("child has no stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ChildError::Protocol("child has no stdout".to_string()))?;

        let mut client = StdioMcpClient {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        };
        client.initialize()?;
        Ok(client)
    }

    fn initialize(&mut self) -> Result<(), ChildError> {
        self.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcp-lockd", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        // Per MCP, follow a successful initialize with this notification.
        self.notify("notifications/initialized", json!({}))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, ChildError> {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.write_line(&message)?;

        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).map_err(ChildError::Io)?;
            if n == 0 {
                return Err(ChildError::Exited);
            }
            if line.trim().is_empty() {
                continue;
            }
            let value: Value =
                serde_json::from_str(&line).map_err(|e| ChildError::Protocol(e.to_string()))?;
            // Skip anything that is not the response to our request (e.g. a
            // notification the child emitted in the meantime).
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                return Err(ChildError::Rpc {
                    code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                });
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), ChildError> {
        let message = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.write_line(&message)
    }

    fn write_line(&mut self, message: &Value) -> Result<(), ChildError> {
        let line =
            serde_json::to_string(message).map_err(|e| ChildError::Protocol(e.to_string()))?;
        self.stdin
            .write_all(line.as_bytes())
            .map_err(ChildError::Io)?;
        self.stdin.write_all(b"\n").map_err(ChildError::Io)?;
        self.stdin.flush().map_err(ChildError::Io)
    }
}

impl McpChild for StdioMcpClient {
    fn list_tools(&mut self) -> Result<Vec<ToolDef>, ChildError> {
        let result = self.request("tools/list", json!({}))?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(tools
            .into_iter()
            .filter_map(|def| {
                def.get("name").and_then(Value::as_str).map(|name| ToolDef {
                    name: name.to_string(),
                    definition: def.clone(),
                })
            })
            .collect())
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, ChildError> {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }
}

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        // The broker owns the child; don't leak it. Best-effort terminate.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
