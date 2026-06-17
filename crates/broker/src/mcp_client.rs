//! Synchronous stdio MCP client for child servers.
//!
//! The broker spawns each MCP server as a child process and speaks
//! newline-delimited JSON-RPC 2.0 to it over the child's stdin/stdout. Because
//! the broker is the parent, it owns the child's lifecycle. Calls are serialized
//! per child (one request, read until the matching response), which is all the
//! aggregator needs and keeps the client simple and synchronous.
//!
//! Reads happen on a dedicated per-child reader thread that pushes parsed lines
//! over an [`mpsc`] channel. The request path then blocks on `recv_timeout`, so a
//! child that hangs (never replies) cannot deadlock the broker: the read times
//! out and surfaces as [`ChildError::Timeout`]. We use a thread + channel rather
//! than a non-blocking read because the workspace denies `unsafe_code` and we
//! must not touch libc/`O_NONBLOCK`; a blocking read on its own thread, abandoned
//! on timeout, is the safe-std way to bound a read.
//!
//! The [`McpChild`] trait is the seam the aggregator depends on, so it can be
//! driven by an in-process fake in tests without spawning anything.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use mcp_lock_core::exec::ExecutionContext;

/// MCP protocol version the broker speaks to children.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Default per-request read timeout. Generous so a legitimately slow tool call
/// is not cut off, but bounded so a hung child cannot block the broker forever.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Cap on a single newline-delimited message the reader will buffer. A child
/// (or a corrupted stream) that never emits a newline must not be able to grow
/// the broker's memory without bound, so the reader fails the line past this
/// length rather than reading forever.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// How long [`Drop`] polls for the killed child to be reaped before giving up.
/// Bounded so dropping a client can never block the broker indefinitely.
const DROP_REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// One item from the reader thread: either a successfully read line, or the IO
/// error that ended the stream. EOF is signalled by dropping the sender (the
/// channel disconnects), not by a value.
type ReadItem = Result<String, std::io::Error>;

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
    /// The child did not reply within the request timeout (it is hung). The
    /// broker treats this like a crash: the child fails closed.
    Timeout,
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
            ChildError::Timeout => write!(f, "child timed out"),
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

    /// Whether the child process is still alive. A supervising caller uses this
    /// to fail a crashed child closed (drop its exposure and elevation) before
    /// recomputing the exposed listing.
    fn is_alive(&mut self) -> bool;
}

/// A child MCP server spoken to over stdio. The broker is its parent.
pub struct StdioMcpClient {
    child: Child,
    stdin: ChildStdin,
    /// Lines read from the child's stdout, pushed by the reader thread. EOF on
    /// stdout disconnects this channel.
    rx: Receiver<ReadItem>,
    /// Handle to the reader thread, joined best-effort on drop. Optional only so
    /// drop can `take()` it.
    reader: Option<JoinHandle<()>>,
    next_id: u64,
    /// Per-request read timeout applied to `rx.recv_timeout`.
    timeout: Duration,
}

// Hand-written: `Child`/`Receiver`/`JoinHandle` are not all Debug, and we want a
// compact, non-leaking representation.
impl fmt::Debug for StdioMcpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdioMcpClient")
            .field("pid", &self.child.id())
            .field("next_id", &self.next_id)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl StdioMcpClient {
    /// Spawn `command` with `args` and `env`, perform the MCP `initialize`
    /// handshake, and return a ready client using [`DEFAULT_REQUEST_TIMEOUT`].
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
        Self::spawn_with_timeout(command, args, ctx, env, DEFAULT_REQUEST_TIMEOUT)
    }

    /// As [`spawn`](Self::spawn), but with an explicit per-request read timeout.
    /// Used by tests to drive the timeout path quickly; the public `spawn`
    /// delegates here with the default.
    pub fn spawn_with_timeout(
        command: &str,
        args: &[String],
        ctx: &ExecutionContext,
        env: &BTreeMap<String, String>,
        timeout: Duration,
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

        let (tx, rx) = mpsc::channel::<ReadItem>();
        // The reader owns the stdout half and pushes lines until EOF (sender
        // dropped on return ⇒ channel disconnects) or the receiver is gone.
        let reader = thread::spawn(move || read_lines(BufReader::new(stdout), &tx));

        let mut client = StdioMcpClient {
            child,
            stdin,
            rx,
            reader: Some(reader),
            next_id: 1,
            timeout,
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

        // The timeout is per request, not per line: a child that drips
        // unrelated notifications must not be able to reset the clock forever.
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            let line = match self.rx.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                // Reader surfaced an IO error (incl. the over-length guard).
                Ok(Err(e)) => return Err(ChildError::Io(e)),
                // No reply within the budget: the child is hung.
                Err(RecvTimeoutError::Timeout) => return Err(ChildError::Timeout),
                // Reader thread gone ⇒ stdout hit EOF ⇒ the child exited.
                Err(RecvTimeoutError::Disconnected) => return Err(ChildError::Exited),
            };
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

/// Reader-thread body: read newline-delimited messages from `reader` and push
/// each over `tx` until EOF, a send failure (receiver gone), or an IO/over-length
/// error. Returns on any of these; returning drops `tx`, which disconnects the
/// channel and is how the request side learns the child's stdout closed.
///
/// We cap each message at [`MAX_LINE_BYTES`] and read byte-bounded chunks rather
/// than `read_line` into an unbounded `String`, so a child that never emits a
/// newline cannot grow the broker's memory without bound.
fn read_lines(mut reader: BufReader<ChildStdout>, tx: &mpsc::Sender<ReadItem>) {
    loop {
        let mut buf: Vec<u8> = Vec::new();
        // `take` bounds this read to one byte past the cap, so an over-length
        // line stops growing memory; we detect the overflow by hitting the cap
        // with no newline consumed.
        let mut limited = (&mut reader).take((MAX_LINE_BYTES as u64) + 1);
        let n = match limited.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(e) => {
                // Best-effort: if the receiver is gone the send fails and we
                // exit anyway.
                let _ = tx.send(Err(e));
                return;
            }
        };
        if n == 0 {
            // EOF: drop `tx` by returning, disconnecting the channel.
            return;
        }
        if buf.len() > MAX_LINE_BYTES {
            let _ = tx.send(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("child message exceeded {MAX_LINE_BYTES} bytes"),
            )));
            return;
        }
        // Decode lossily so an invalid-UTF-8 byte surfaces downstream as a
        // protocol (parse) error rather than panicking the reader thread.
        let line = String::from_utf8_lossy(&buf).into_owned();
        if tx.send(Ok(line)).is_err() {
            // Receiver dropped (client gone): nothing more to do.
            return;
        }
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

    fn is_alive(&mut self) -> bool {
        // `try_wait` does not block. `Ok(None)` means still running; an exit
        // status or an error (we can't tell ⇒ assume dead) fails closed.
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        // The broker owns the child; don't leak it. Best-effort terminate, then
        // reap with a *bounded* poll loop so a child that ignores the kill (or a
        // reap that wedges) can never block drop forever.
        let _ = self.child.kill();
        let deadline = Instant::now() + DROP_REAP_TIMEOUT;
        loop {
            match self.child.try_wait() {
                // Reaped, or we can't tell — either way stop polling.
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
        // Do NOT join the reader thread: if the child ignored the kill, the
        // reader is still blocked on a read of its stdout and joining would
        // reintroduce the unbounded wait this method exists to avoid. We detach
        // it instead — once the OS finally tears the child down, the read hits
        // EOF and the thread exits on its own.
        drop(self.reader.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that reads nothing and never replies must not be able to hang the
    /// broker: with a short timeout, the very first request (the `initialize`
    /// handshake inside `spawn_with_timeout`) returns `Timeout` quickly rather
    /// than blocking forever.
    #[test]
    fn hung_child_times_out_quickly() {
        // `/bin/sleep` ignores its stdin and never writes stdout, so it stands
        // in for a hung MCP server. A long arg guarantees it outlives the test.
        let ctx = ExecutionContext::first_party(Vec::new());
        let env = BTreeMap::new();
        let timeout = Duration::from_millis(200);

        let start = Instant::now();
        let result = StdioMcpClient::spawn_with_timeout(
            "/bin/sleep",
            &["3600".to_string()],
            &ctx,
            &env,
            timeout,
        );
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ChildError::Timeout)),
            "expected Timeout, got {result:?}"
        );
        // Must time out promptly — give generous slack for a loaded CI box but
        // far below the 1h sleep, proving the read was actually bounded.
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout took too long: {elapsed:?}"
        );
    }
}
