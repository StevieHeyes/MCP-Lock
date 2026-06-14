//! The broker's [`ControlHandler`]: observe + lifecycle over the control
//! channel, against the shared aggregator.
//!
//! Lifecycle commands carry no presence (Slice 4); each can only reduce exposure
//! or bring a server up read-only. When a command changes the exposed tool set,
//! the broker fires MCP `tools/list_changed` to connected endpoint clients via
//! the shared [`Notifier`].

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mcp_lock_core::audit::{AuditEvent, AuditLog};
use mcp_lock_core::elevation::{
    ClientRegistry, ElevationError, Nonce, NonceStore, Purpose, RequestedMode, Verified,
};
use mcp_lock_core::policy::{Elevation, ServerState, Timestamp};
use mcp_lock_transport::control::{ControlHandler, ControlRequest, ControlResponse, ServerStatus};
use mcp_lock_transport::endpoint::Notifier;

use crate::aggregator::Aggregator;

const DEFAULT_LOG_LIMIT: usize = 50;
const MAX_LOG_ENTRIES: usize = 500;

/// Control handler backed by the shared aggregator.
pub struct BrokerControlHandler {
    aggregator: Arc<Mutex<Aggregator>>,
    notifier: Notifier,
    /// Issues/verifies elevation and confirm nonces.
    nonces: Mutex<NonceStore>,
    /// Registered client signing keys (read-only after load). Empty = ship closed.
    registry: Arc<ClientRegistry>,
    /// The append-only security audit tape.
    audit: Arc<AuditLog>,
    clock_base: Instant,
    log: Mutex<VecDeque<String>>,
}

impl std::fmt::Debug for BrokerControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerControlHandler").finish()
    }
}

impl BrokerControlHandler {
    /// Create a handler over the shared aggregator and notifier, with the client
    /// registry (signing keys) and the audit log.
    pub fn new(
        aggregator: Arc<Mutex<Aggregator>>,
        notifier: Notifier,
        registry: Arc<ClientRegistry>,
        audit: Arc<AuditLog>,
    ) -> Self {
        let handler = BrokerControlHandler {
            aggregator,
            notifier,
            nonces: Mutex::new(NonceStore::new()),
            registry,
            audit,
            clock_base: Instant::now(),
            log: Mutex::new(VecDeque::new()),
        };
        handler.record("broker control channel ready");
        handler
    }

    fn now(&self) -> Timestamp {
        self.clock_base.elapsed().as_secs()
    }

    fn record(&self, message: impl Into<String>) {
        if let Ok(mut log) = self.log.lock() {
            log.push_back(format!("[t+{}s] {}", self.now(), message.into()));
            while log.len() > MAX_LOG_ENTRIES {
                log.pop_front();
            }
        }
    }

    fn status(&self) -> ControlResponse {
        let now = self.now();
        let Ok(agg) = self.aggregator.lock() else {
            return internal_error();
        };
        let servers = agg
            .state()
            .servers()
            .iter()
            .map(|slot| ServerStatus {
                id: slot.id().to_string(),
                state: state_name(slot.state()).to_string(),
                exposed_tools: slot.exposed(now).len(),
                elevated: slot.elevation().is_some(),
            })
            .collect();
        ControlResponse::Status { servers }
    }

    fn list(&self) -> ControlResponse {
        let now = self.now();
        let Ok(agg) = self.aggregator.lock() else {
            return internal_error();
        };
        let tools = agg
            .aggregated_tools(now)
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        ControlResponse::List { tools }
    }

    fn logs(&self, limit: Option<usize>) -> ControlResponse {
        let limit = limit.unwrap_or(DEFAULT_LOG_LIMIT);
        let Ok(log) = self.log.lock() else {
            return internal_error();
        };
        let entries = log
            .iter()
            .rev()
            .take(limit)
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        ControlResponse::Logs { entries }
    }

    /// Run a lifecycle op, firing `tools/list_changed` if exposure changed.
    fn lifecycle(&self, op: LifecycleOp, id: &str) -> ControlResponse {
        let now = self.now();
        let (changed, result) = {
            let Ok(mut agg) = self.aggregator.lock() else {
                return internal_error();
            };
            let before = agg.exposure_snapshot(now);
            let result = match op {
                LifecycleOp::Start => agg.start(id),
                LifecycleOp::Stop => agg.stop(id),
                LifecycleOp::Pause => agg.pause(id),
                LifecycleOp::Resume => agg.resume(id),
            };
            let changed = result.is_ok() && agg.exposure_snapshot(now) != before;
            (changed, result)
        };

        match result {
            Ok(()) => {
                if changed {
                    self.notifier.notify_tools_list_changed();
                }
                self.record(format!("{} {id}", op.verb()));
                ControlResponse::Done {
                    message: format!("{} {id}: ok", op.verb()),
                }
            }
            Err(e) => {
                self.record(format!("{} {id} failed: {e}", op.verb()));
                ControlResponse::Error {
                    message: e.to_string(),
                }
            }
        }
    }

    /// Step 1 of elevation: issue a nonce bound to the requested write window.
    fn request_elevation(
        &self,
        client_id: String,
        server_id: String,
        mode: &str,
        ttl_secs: Option<u64>,
    ) -> ControlResponse {
        let mode = match (mode, ttl_secs) {
            ("duration", Some(ttl)) => RequestedMode::Duration { ttl_secs: ttl },
            ("until_revoked", _) => RequestedMode::UntilRevoked,
            ("duration", None) => {
                return err("duration mode requires ttl_secs");
            }
            _ => return err("mode must be \"duration\" or \"until_revoked\""),
        };
        self.issue(client_id, Purpose::Elevate { server_id, mode })
    }

    /// Step 1 of per-action confirm: issue a nonce bound to one tool.
    fn request_confirm(
        &self,
        client_id: String,
        server_id: String,
        tool: String,
    ) -> ControlResponse {
        self.issue(client_id, Purpose::Confirm { server_id, tool })
    }

    fn issue(&self, client_id: String, purpose: Purpose) -> ControlResponse {
        let now = self.now();
        let Ok(mut nonces) = self.nonces.lock() else {
            return internal_error();
        };
        match nonces.issue(client_id, purpose, now) {
            Ok(nonce) => ControlResponse::Nonce {
                nonce: nonce.to_hex(),
            },
            Err(e) => err(&e.to_string()),
        }
    }

    /// Step 2: verify a signed assertion and consume its nonce, then apply it.
    fn submit(&self, client_id: &str, nonce_hex: &str, signature_hex: &str) -> ControlResponse {
        let now = self.now();
        let Some(nonce) = Nonce::from_hex(nonce_hex) else {
            return err("malformed nonce");
        };
        let Some(signature) = decode_hex(signature_hex) else {
            return err("malformed signature");
        };

        let verified = {
            let Ok(mut nonces) = self.nonces.lock() else {
                return internal_error();
            };
            nonces.verify_and_consume(client_id, &nonce, &signature, &self.registry, now)
        };

        match verified {
            Ok(Verified::Elevation {
                server_id,
                elevation,
            }) => self.apply_elevation(client_id, &server_id, elevation, now),
            Ok(Verified::Confirm { server_id, tool }) => self.apply_confirm(&server_id, &tool, now),
            Err(e) => {
                // A failed verification is security-relevant; record it.
                self.record(format!("elevation rejected for {client_id}: {e}"));
                reject(e)
            }
        }
    }

    fn apply_elevation(
        &self,
        client_id: &str,
        server_id: &str,
        elevation: Elevation,
        now: Timestamp,
    ) -> ControlResponse {
        let mode = match elevation.mode() {
            mcp_lock_core::policy::ElevationMode::Duration => "duration",
            mcp_lock_core::policy::ElevationMode::UntilRevoked => "until_revoked",
        };
        let changed = {
            let Ok(mut agg) = self.aggregator.lock() else {
                return internal_error();
            };
            let before = agg.exposure_snapshot(now);
            let Some(slot) = agg.state_mut().server_mut(server_id) else {
                return err(&format!("unknown server: {server_id}"));
            };
            slot.grant_elevation(elevation);
            agg.exposure_snapshot(now) != before
        };
        if changed {
            self.notifier.notify_tools_list_changed();
        }
        self.audit.record(AuditEvent::ElevationGranted {
            server_id: server_id.to_string(),
            client_id: client_id.to_string(),
            mode: mode.to_string(),
        });
        self.record(format!("elevation granted on {server_id} ({mode})"));
        ControlResponse::Done {
            message: format!("elevated {server_id} ({mode})"),
        }
    }

    fn apply_confirm(&self, server_id: &str, tool: &str, now: Timestamp) -> ControlResponse {
        {
            let Ok(mut agg) = self.aggregator.lock() else {
                return internal_error();
            };
            agg.approve_action(server_id, tool, now);
        }
        self.audit.record(AuditEvent::ConfirmApproved {
            server_id: server_id.to_string(),
            tool: tool.to_string(),
        });
        self.record(format!("confirm approved for {server_id}.{tool}"));
        ControlResponse::Done {
            message: format!("confirmed {server_id}.{tool} (single use)"),
        }
    }

    fn revoke(&self, server_id: &str) -> ControlResponse {
        let now = self.now();
        let changed = {
            let Ok(mut agg) = self.aggregator.lock() else {
                return internal_error();
            };
            let before = agg.exposure_snapshot(now);
            let Some(slot) = agg.state_mut().server_mut(server_id) else {
                return err(&format!("unknown server: {server_id}"));
            };
            slot.revoke_elevation();
            agg.exposure_snapshot(now) != before
        };
        if changed {
            self.notifier.notify_tools_list_changed();
        }
        self.audit.record(AuditEvent::ElevationRevoked {
            server_id: server_id.to_string(),
            reason: "operator".to_string(),
        });
        self.record(format!("elevation revoked on {server_id}"));
        ControlResponse::Done {
            message: format!("revoked {server_id}"),
        }
    }
}

impl ControlHandler for BrokerControlHandler {
    fn handle(&self, request: ControlRequest) -> ControlResponse {
        match request {
            ControlRequest::Status => self.status(),
            ControlRequest::List => self.list(),
            ControlRequest::Logs { limit } => self.logs(limit),
            ControlRequest::Start { id } => self.lifecycle(LifecycleOp::Start, &id),
            ControlRequest::Stop { id } => self.lifecycle(LifecycleOp::Stop, &id),
            ControlRequest::Pause { id } => self.lifecycle(LifecycleOp::Pause, &id),
            ControlRequest::Resume { id } => self.lifecycle(LifecycleOp::Resume, &id),
            ControlRequest::RequestElevation {
                client_id,
                server_id,
                mode,
                ttl_secs,
            } => self.request_elevation(client_id, server_id, &mode, ttl_secs),
            ControlRequest::SubmitElevation {
                client_id,
                nonce,
                signature,
            } => self.submit(&client_id, &nonce, &signature),
            ControlRequest::RequestConfirm {
                client_id,
                server_id,
                tool,
            } => self.request_confirm(client_id, server_id, tool),
            ControlRequest::SubmitConfirm {
                client_id,
                nonce,
                signature,
            } => self.submit(&client_id, &nonce, &signature),
            ControlRequest::Revoke { id } => self.revoke(&id),
        }
    }
}

fn err(message: &str) -> ControlResponse {
    ControlResponse::Error {
        message: message.to_string(),
    }
}

/// Map a verification failure to a coarse client-facing error (no oracle on
/// exactly why beyond what the operator needs).
fn reject(e: ElevationError) -> ControlResponse {
    err(&format!("elevation rejected: {e}"))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

#[derive(Clone, Copy)]
enum LifecycleOp {
    Start,
    Stop,
    Pause,
    Resume,
}

impl LifecycleOp {
    fn verb(self) -> &'static str {
        match self {
            LifecycleOp::Start => "start",
            LifecycleOp::Stop => "stop",
            LifecycleOp::Pause => "pause",
            LifecycleOp::Resume => "resume",
        }
    }
}

fn state_name(state: ServerState) -> &'static str {
    match state {
        ServerState::Running => "running",
        ServerState::Paused => "paused",
        ServerState::Stopped => "stopped",
    }
}

fn internal_error() -> ControlResponse {
    ControlResponse::Error {
        message: "internal error".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_lock_core::manifest::load_from_bytes;
    use serde_json::{json, Value};

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
        fn call_tool(&mut self, _name: &str, _args: Value) -> Result<Value, ChildError> {
            Ok(json!({}))
        }
        fn is_alive(&mut self) -> bool {
            true
        }
    }

    const MANIFEST: &[u8] =
        br#"{"servers":[{"id":"mail","command":"x","tools":{"search":"read","delete_message":"write"}}]}"#;

    fn handler() -> BrokerControlHandler {
        handler_with_registry(ClientRegistry::new())
    }

    fn handler_with_registry(registry: ClientRegistry) -> BrokerControlHandler {
        let loaded = load_from_bytes(MANIFEST).unwrap();
        let agg =
            Aggregator::build(&loaded, |_| Ok(Box::new(FakeChild) as Box<dyn McpChild>)).unwrap();
        BrokerControlHandler::new(
            Arc::new(Mutex::new(agg)),
            Notifier::new(),
            Arc::new(registry),
            Arc::new(AuditLog::in_memory()),
        )
    }

    #[test]
    fn status_reports_running_read_only() {
        let h = handler();
        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!("expected status");
        };
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].state, "running");
        assert_eq!(servers[0].exposed_tools, 1); // only search (read)
        assert!(!servers[0].elevated);
    }

    #[test]
    fn list_shows_namespaced_read_tools() {
        let h = handler();
        let ControlResponse::List { tools } = h.handle(ControlRequest::List) else {
            panic!("expected list");
        };
        assert_eq!(tools, vec!["mail.search"]);
    }

    #[test]
    fn pause_then_status_shows_paused_and_logs_it() {
        let h = handler();
        let resp = h.handle(ControlRequest::Pause {
            id: "mail".to_string(),
        });
        assert!(matches!(resp, ControlResponse::Done { .. }));

        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!("status");
        };
        assert_eq!(servers[0].state, "paused");
        assert_eq!(servers[0].exposed_tools, 0);

        let ControlResponse::Logs { entries } = h.handle(ControlRequest::Logs { limit: None })
        else {
            panic!("logs");
        };
        assert!(entries.iter().any(|e| e.contains("pause mail")));
    }

    #[test]
    fn lifecycle_on_unknown_server_is_an_error() {
        let h = handler();
        let resp = h.handle(ControlRequest::Stop {
            id: "nope".to_string(),
        });
        assert!(matches!(resp, ControlResponse::Error { .. }));
    }

    #[test]
    fn stop_then_start_returns_to_running() {
        let h = handler();
        assert!(matches!(
            h.handle(ControlRequest::Stop { id: "mail".into() }),
            ControlResponse::Done { .. }
        ));
        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!("status");
        };
        assert_eq!(servers[0].state, "stopped");

        assert!(matches!(
            h.handle(ControlRequest::Start { id: "mail".into() }),
            ControlResponse::Done { .. }
        ));
        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!("status");
        };
        assert_eq!(servers[0].state, "running");
        assert_eq!(servers[0].exposed_tools, 1);
    }

    #[test]
    fn unregistered_client_cannot_elevate() {
        // Empty registry -> ship closed: even a well-formed request is rejected
        // at submit time (no key to verify against).
        let h = handler();
        let ControlResponse::Nonce { nonce } = h.handle(ControlRequest::RequestElevation {
            client_id: "client-1".into(),
            server_id: "mail".into(),
            mode: "duration".into(),
            ttl_secs: Some(300),
        }) else {
            panic!("expected a nonce");
        };
        // Any signature is rejected because the client is unknown.
        let resp = h.handle(ControlRequest::SubmitElevation {
            client_id: "client-1".into(),
            nonce,
            signature: "00".repeat(64),
        });
        assert!(matches!(resp, ControlResponse::Error { .. }));
    }

    #[test]
    fn full_elevation_round_trip_flips_exposure_and_audits() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let mut registry = ClientRegistry::new();
        registry
            .register("client-1", &signing.verifying_key().to_bytes())
            .unwrap();
        let h = handler_with_registry(registry);

        // Read-only to start: only `search`.
        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!()
        };
        assert_eq!(servers[0].exposed_tools, 1);

        // Step 1: request a nonce.
        let ControlResponse::Nonce { nonce } = h.handle(ControlRequest::RequestElevation {
            client_id: "client-1".into(),
            server_id: "mail".into(),
            mode: "duration".into(),
            ttl_secs: Some(300),
        }) else {
            panic!("expected a nonce");
        };

        // Step 2: sign the canonical challenge with the presence-key stand-in.
        let nonce_obj = Nonce::from_hex(&nonce).unwrap();
        let purpose = Purpose::Elevate {
            server_id: "mail".into(),
            mode: RequestedMode::Duration { ttl_secs: 300 },
        };
        let message = mcp_lock_core::elevation::challenge_message(&nonce_obj, "client-1", &purpose);
        let signature = signing.sign(&message);
        let sig_hex: String = signature
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let resp = h.handle(ControlRequest::SubmitElevation {
            client_id: "client-1".into(),
            nonce,
            signature: sig_hex,
        });
        assert!(matches!(resp, ControlResponse::Done { .. }), "got {resp:?}");

        // Now elevated: write tool exposed too.
        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!()
        };
        assert_eq!(servers[0].exposed_tools, 2);
        assert!(servers[0].elevated);

        // The audit tape recorded the grant.
        assert!(h
            .audit
            .recent(10)
            .iter()
            .any(|e| e.contains("elevation_granted")));

        // Revoke returns to read-only.
        assert!(matches!(
            h.handle(ControlRequest::Revoke { id: "mail".into() }),
            ControlResponse::Done { .. }
        ));
        let ControlResponse::Status { servers } = h.handle(ControlRequest::Status) else {
            panic!()
        };
        assert_eq!(servers[0].exposed_tools, 1);
        assert!(!servers[0].elevated);
    }
}
