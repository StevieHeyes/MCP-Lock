//! The upward MCP endpoint: a synchronous, bearer-authenticated HTTP server.
//!
//! This is the Claude-client-facing side of the broker. It is deliberately
//! transport-only: it authenticates with the pluggable
//! [`CredentialValidator`](mcp_lock_core::auth::CredentialValidator) seam and
//! delegates every JSON-RPC request to an [`McpHandler`] (implemented by the
//! broker over its aggregator). It knows nothing about tools, classification, or
//! exposure — that is the security core's job.
//!
//! Transport shape (a pragmatic subset of MCP Streamable HTTP):
//! * `POST` — one JSON-RPC request in the body, one JSON response back. A
//!   notification (no `id`) gets `202 Accepted` with no body.
//! * `GET` — a Server-Sent Events stream the broker pushes notifications on
//!   (e.g. `notifications/tools/list_changed`), via [`Notifier`].
//! * Every request must carry `Authorization: Bearer <token>`; otherwise `401`.
//!
//! v1 binds loopback only. TLS / remote (mTLS over Tailscale) is a documented
//! follow-up and stays out of this file by design.

use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use mcp_lock_core::auth::{CredentialValidator, ValidatedClient};

/// Handles a single authenticated JSON-RPC request and returns the response
/// object. Implemented by the broker over its aggregator.
///
/// The `client` argument is proof the request was authenticated — the endpoint
/// cannot call this without a [`ValidatedClient`].
pub trait McpHandler: Send + Sync {
    /// Handle one JSON-RPC request object, returning the response object.
    fn handle(&self, request: &Value, client: &ValidatedClient) -> Value;
}

/// Broadcasts server-to-client notifications to all connected SSE subscribers.
///
/// Cloneable and shared: the broker keeps one and calls
/// [`Notifier::notify_tools_list_changed`] whenever exposure changes (wired in
/// the lifecycle/elevation slices). Dead subscribers are dropped on the next
/// broadcast.
#[derive(Clone, Default)]
pub struct Notifier {
    subscribers: Arc<Mutex<Vec<Sender<String>>>>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.subscribers.lock().map(|s| s.len()).unwrap_or(0);
        f.debug_struct("Notifier")
            .field("subscribers", &count)
            .finish()
    }
}

impl Notifier {
    /// A notifier with no subscribers.
    pub fn new() -> Self {
        Notifier::default()
    }

    fn subscribe(&self) -> Receiver<String> {
        let (tx, rx) = channel();
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.push(tx);
        }
        rx
    }

    /// Broadcast a JSON-RPC notification to every connected SSE client.
    pub fn notify(&self, method: &str, params: Value) {
        let message = json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string();
        if let Ok(mut subs) = self.subscribers.lock() {
            // Drop any subscriber whose receiver has gone away.
            subs.retain(|tx| tx.send(message.clone()).is_ok());
        }
    }

    /// Broadcast the MCP `tools/list_changed` notification.
    pub fn notify_tools_list_changed(&self) {
        self.notify("notifications/tools/list_changed", json!({}));
    }

    /// Number of currently-connected subscribers (for tests/diagnostics).
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// A `Read` that turns broadcast notification strings into an SSE byte stream.
///
/// It blocks until the next notification arrives, then yields one `data: …\n\n`
/// frame. When the sender side is dropped it returns EOF, ending the response.
struct SseReader {
    rx: Receiver<String>,
    buf: Vec<u8>,
    pos: usize,
}

impl SseReader {
    fn new(rx: Receiver<String>) -> Self {
        // An initial SSE comment so the stream (and its headers) is established
        // immediately, before any real event.
        SseReader {
            rx,
            buf: b": connected\n\n".to_vec(),
            pos: 0,
        }
    }
}

impl Read for SseReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(message) => {
                    self.buf = format!("data: {message}\n\n").into_bytes();
                    self.pos = 0;
                }
                // Sender dropped: end the stream.
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// The HTTP MCP endpoint.
pub struct HttpEndpoint {
    server: Server,
    local_addr: SocketAddr,
    validator: Arc<dyn CredentialValidator>,
    handler: Arc<dyn McpHandler>,
    notifier: Notifier,
}

impl std::fmt::Debug for HttpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEndpoint")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl HttpEndpoint {
    /// Bind the endpoint to `addr` (use a loopback address in v1). Returns an
    /// error if binding fails or the bound address is not an IP socket.
    pub fn bind(
        addr: &str,
        validator: Arc<dyn CredentialValidator>,
        handler: Arc<dyn McpHandler>,
        notifier: Notifier,
    ) -> io::Result<Self> {
        let server = Server::http(addr).map_err(|e| io::Error::other(e.to_string()))?;
        let local_addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| io::Error::other("endpoint is not an IP socket"))?;
        Ok(HttpEndpoint {
            server,
            local_addr,
            validator,
            handler,
            notifier,
        })
    }

    /// The address the endpoint is listening on (useful when binding to port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// A handle for broadcasting notifications to connected SSE clients.
    pub fn notifier(&self) -> Notifier {
        self.notifier.clone()
    }

    /// Serve requests forever. Each request is handled on its own thread so a
    /// long-lived SSE stream does not block other requests.
    pub fn run(&self) {
        for request in self.server.incoming_requests() {
            let validator = self.validator.clone();
            let handler = self.handler.clone();
            let notifier = self.notifier.clone();
            std::thread::spawn(move || {
                handle_request(request, validator.as_ref(), handler.as_ref(), &notifier);
            });
        }
    }
}

fn bearer_token(request: &Request) -> Option<String> {
    let header = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))?;
    let value = header.value.as_str();
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(|t| t.trim().to_string())
}

fn json_response(body: String, status: u16) -> Response<io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header is valid");
    Response::from_string(body)
        .with_status_code(status)
        .with_header(header)
}

fn handle_request(
    request: Request,
    validator: &dyn CredentialValidator,
    handler: &dyn McpHandler,
    notifier: &Notifier,
) {
    // Authenticate first. Both Missing and Invalid map to the same 401 so we
    // reveal nothing about which it was.
    let token = bearer_token(&request);
    let client = match validator.validate(token.as_deref()) {
        Ok(client) => client,
        Err(_) => {
            let header =
                Header::from_bytes(&b"WWW-Authenticate"[..], &b"Bearer"[..]).expect("valid");
            let _ = request.respond(
                Response::from_string("unauthorized")
                    .with_status_code(401)
                    .with_header(header),
            );
            return;
        }
    };

    match request.method() {
        Method::Post => handle_post(request, handler, &client),
        Method::Get => handle_sse(request, notifier),
        _ => {
            let _ = request.respond(Response::empty(405));
        }
    }
}

fn handle_post(mut request: Request, handler: &dyn McpHandler, client: &ValidatedClient) {
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        let _ = request.respond(json_response(parse_error_body(), 400));
        return;
    }

    let parsed: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => {
            let _ = request.respond(json_response(parse_error_body(), 400));
            return;
        }
    };

    // A notification (no id) is accepted but not answered with a JSON-RPC body.
    if parsed.get("id").is_none() {
        let _ = request.respond(Response::empty(202));
        return;
    }

    let response = handler.handle(&parsed, client);
    let body = serde_json::to_string(&response).unwrap_or_else(|_| internal_error_body());
    let _ = request.respond(json_response(body, 200));
}

fn handle_sse(request: Request, notifier: &Notifier) {
    let rx = notifier.subscribe();
    let headers = vec![
        Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).expect("valid"),
        Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).expect("valid"),
    ];
    let reader = SseReader::new(rx);
    // data_length = None -> chunked transfer; the stream stays open until the
    // client disconnects or the sender is dropped.
    let response = Response::new(200.into(), headers, reader, None, None);
    let _ = request.respond(response);
}

fn parse_error_body() -> String {
    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}).to_string()
}

fn internal_error_body() -> String {
    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}})
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifier_broadcasts_to_subscribers_and_drops_dead_ones() {
        let n = Notifier::new();
        let rx = n.subscribe();
        assert_eq!(n.subscriber_count(), 1);
        n.notify_tools_list_changed();
        let got = rx.recv().unwrap();
        assert!(got.contains("notifications/tools/list_changed"));

        drop(rx);
        // Broadcasting after the receiver is gone prunes the dead subscriber.
        n.notify("x", json!({}));
        assert_eq!(n.subscriber_count(), 0);
    }

    #[test]
    fn sse_reader_emits_connected_comment_then_events_then_eof() {
        let (tx, rx) = channel();
        tx.send("hello".to_string()).unwrap();
        drop(tx); // so the stream ends after draining
        let mut reader = SseReader::new(rx);
        let mut out = String::new();
        reader.read_to_string(&mut out).unwrap();
        assert!(out.starts_with(": connected\n\n"));
        assert!(out.contains("data: hello\n\n"));
    }
}
