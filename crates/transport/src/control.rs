//! The local control channel: a Unix-domain-socket request/response link the
//! `mcp-lock` CLI uses to observe and drive lifecycle on the broker.
//!
//! Scope and security (v1, Slice 4): the channel carries **observe** (status,
//! list, logs) and **lifecycle** (start/stop/pause/resume) only — never
//! elevation. Lifecycle requires no presence and can only reduce access or bring
//! a server up read-only, so the worst a control-channel attacker achieves is
//! denial of service, never escalation (see `docs/DESIGN.md`).
//!
//! Access control here is the socket's filesystem permissions: it is created
//! `0600`, owned by the broker's account. Peer code-signature verification and
//! the presence-gated elevation protocol are added in Slice 5 (`[SECURITY-REVIEW]`),
//! which is also where the remote (mTLS) variant lives. This module is local-only
//! and Unix-only.
//!
//! Wire format: one JSON request line in, one JSON response line back.

#![cfg(unix)]

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Environment variable overriding the control-socket path.
pub const SOCKET_ENV: &str = "MCPLOCK_CONTROL_SOCK";

/// The control-socket path: `$MCPLOCK_CONTROL_SOCK`, or
/// `<tmpdir>/mcp-lock/control.sock`. Both the broker (to bind) and the CLI (to
/// connect) call this, so they agree. The default nests the socket in its own
/// directory so [`ControlServer::bind`] can make that directory owner-only.
pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("mcp-lock").join("control.sock"))
}

/// A control request from the CLI to the broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Report each server's state and exposure.
    Status,
    /// List the currently-exposed (namespaced) tool names.
    List,
    /// Return recent broker log lines.
    Logs {
        /// Maximum number of lines to return (most recent first). `None` = a
        /// server-chosen default.
        #[serde(default)]
        limit: Option<usize>,
    },
    /// Start (or restart) a server. Comes up read-only.
    Start {
        /// Server id.
        id: String,
    },
    /// Stop a server (terminate its process; expose nothing).
    Stop {
        /// Server id.
        id: String,
    },
    /// Pause a server (routing-level; process keeps running).
    Pause {
        /// Server id.
        id: String,
    },
    /// Resume a paused server.
    Resume {
        /// Server id.
        id: String,
    },
}

/// One server's status line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerStatus {
    /// Server id.
    pub id: String,
    /// `"running"`, `"paused"`, or `"stopped"`.
    pub state: String,
    /// Number of tools currently exposed.
    pub exposed_tools: usize,
    /// Whether the server has an active elevation (always false until Slice 5).
    pub elevated: bool,
}

/// A control response from the broker to the CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    /// Reply to [`ControlRequest::Status`].
    Status {
        /// One entry per supervised server.
        servers: Vec<ServerStatus>,
    },
    /// Reply to [`ControlRequest::List`].
    List {
        /// Currently-exposed, namespaced tool names.
        tools: Vec<String>,
    },
    /// Reply to [`ControlRequest::Logs`].
    Logs {
        /// Recent log lines, most recent last.
        entries: Vec<String>,
    },
    /// Reply to a lifecycle command.
    Done {
        /// Human-readable confirmation.
        message: String,
    },
    /// Any failure (unknown server, IO, etc.).
    Error {
        /// Human-readable reason.
        message: String,
    },
}

/// Handles control requests on the broker side.
pub trait ControlHandler: Send + Sync {
    /// Handle one request and produce a response.
    fn handle(&self, request: ControlRequest) -> ControlResponse;
}

/// CLI-side client: one request, one response, over the control socket.
#[derive(Debug)]
pub struct ControlClient;

impl ControlClient {
    /// Send `request` to the broker listening at `socket_path` and return its
    /// response.
    pub fn request(socket_path: &Path, request: &ControlRequest) -> io::Result<ControlResponse> {
        let stream = UnixStream::connect(socket_path)?;
        let mut writer = stream.try_clone()?;
        let line = serde_json::to_string(request).map_err(io::Error::other)?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        // A clean EOF here (0 bytes) means the broker accepted the connection
        // but closed it without writing a response — report that accurately
        // rather than letting an empty string surface as a confusing JSON parse
        // error that reads like "broker unreachable".
        if reader.read_line(&mut response_line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "broker closed the control connection without a response",
            ));
        }
        serde_json::from_str(&response_line).map_err(io::Error::other)
    }
}

/// Broker-side listener for the control channel.
#[derive(Debug)]
pub struct ControlServer {
    listener: UnixListener,
}

impl ControlServer {
    /// Bind the control socket at `path`, replacing any stale socket file, and
    /// restrict it to owner-only (`0600`).
    pub fn bind(path: &Path) -> io::Result<Self> {
        // Create the socket's parent directory owner-only first. `UnixListener::bind`
        // creates the socket with `0777 & !umask`, leaving a brief window before the
        // `set_permissions` below during which a colocated user could connect. A
        // `0700` parent closes that window without needing `umask` (which would be
        // unsafe/libc, forbidden here). `DirBuilder` applies the mode only to
        // directories it creates, so an existing shared dir (e.g. the temp dir) is
        // never relaxed or tightened.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        // Remove a stale socket from a previous run; ignore if absent.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(ControlServer { listener })
    }

    /// Serve requests forever, one thread per connection.
    pub fn run(&self, handler: Arc<dyn ControlHandler>) {
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = handler.clone();
            std::thread::spawn(move || serve_connection(stream, handler.as_ref()));
        }
    }
}

fn serve_connection(stream: UnixStream, handler: &dyn ControlHandler) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }

    let response = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(request) => handler.handle(request),
        Err(e) => ControlResponse::Error {
            message: format!("bad request: {e}"),
        },
    };

    if let Ok(mut out) = serde_json::to_string(&response) {
        out.push('\n');
        let _ = writer.write_all(out.as_bytes());
        let _ = writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_serde_roundtrip() {
        let req = ControlRequest::Pause {
            id: "mail".to_string(),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<ControlRequest>(&s).unwrap(), req);

        let resp = ControlResponse::Status {
            servers: vec![ServerStatus {
                id: "mail".to_string(),
                state: "running".to_string(),
                exposed_tools: 3,
                elevated: false,
            }],
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<ControlResponse>(&s).unwrap(), resp);
    }

    struct EchoHandler;
    impl ControlHandler for EchoHandler {
        fn handle(&self, request: ControlRequest) -> ControlResponse {
            match request {
                ControlRequest::List => ControlResponse::List {
                    tools: vec!["mail.search".to_string()],
                },
                other => ControlResponse::Done {
                    message: format!("{other:?}"),
                },
            }
        }
    }

    #[test]
    fn client_server_round_trip_over_a_real_socket() {
        let dir = std::env::temp_dir();
        // A unique-enough path for a test socket.
        let path = dir.join(format!("mcp-lock-test-{}.sock", std::process::id()));
        let server = ControlServer::bind(&path).unwrap();

        // Socket is owner-only.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let handler: Arc<dyn ControlHandler> = Arc::new(EchoHandler);
        let server_path = path.clone();
        std::thread::spawn(move || server.run(handler));

        // Give the listener a moment, then make a request.
        let resp = retry_request(&server_path, &ControlRequest::List);
        assert_eq!(
            resp,
            ControlResponse::List {
                tools: vec!["mail.search".to_string()]
            }
        );

        let resp = retry_request(&server_path, &ControlRequest::Pause { id: "x".into() });
        assert!(matches!(resp, ControlResponse::Done { .. }));

        let _ = std::fs::remove_file(&server_path);
    }

    fn retry_request(path: &Path, req: &ControlRequest) -> ControlResponse {
        for _ in 0..50 {
            if let Ok(resp) = ControlClient::request(path, req) {
                return resp;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("control request never succeeded");
    }

    #[test]
    fn bind_makes_the_socket_parent_owner_only() {
        let dir = std::env::temp_dir().join(format!("mcp-lock-test-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("control.sock");
        let _server = ControlServer::bind(&path).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the socket's parent dir is owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn request_reports_eof_when_broker_closes_without_responding() {
        // A listener that accepts a connection and immediately drops it (closing
        // the socket) without writing a response. The client must surface a
        // clear UnexpectedEof, not a misleading parse/"unreachable" error.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mcp-lock-test-eof-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                // Read (consume) the request so the client's write succeeds,
                // then close without writing a response — the broker accepted
                // but produced nothing, which the client must report as EOF.
                let mut line = String::new();
                let _ = BufReader::new(&stream).read_line(&mut line);
                drop(stream);
            }
        });

        let err = ControlClient::request(&path, &ControlRequest::List)
            .expect_err("a connection closed without a response must be an error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        handle.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
