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

use mcp_lock_core::policy::{ServerState, Timestamp};
use mcp_lock_transport::control::{ControlHandler, ControlRequest, ControlResponse, ServerStatus};
use mcp_lock_transport::endpoint::Notifier;

use crate::aggregator::Aggregator;

const DEFAULT_LOG_LIMIT: usize = 50;
const MAX_LOG_ENTRIES: usize = 500;

/// Control handler backed by the shared aggregator.
pub struct BrokerControlHandler {
    aggregator: Arc<Mutex<Aggregator>>,
    notifier: Notifier,
    clock_base: Instant,
    log: Mutex<VecDeque<String>>,
}

impl std::fmt::Debug for BrokerControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerControlHandler").finish()
    }
}

impl BrokerControlHandler {
    /// Create a handler over the shared aggregator and notifier.
    pub fn new(aggregator: Arc<Mutex<Aggregator>>, notifier: Notifier) -> Self {
        let handler = BrokerControlHandler {
            aggregator,
            notifier,
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
        }
    }
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
    }

    const MANIFEST: &[u8] =
        br#"{"servers":[{"id":"mail","command":"x","tools":{"search":"read","delete_message":"write"}}]}"#;

    fn handler() -> BrokerControlHandler {
        let loaded = load_from_bytes(MANIFEST).unwrap();
        let agg =
            Aggregator::build(&loaded, |_| Ok(Box::new(FakeChild) as Box<dyn McpChild>)).unwrap();
        BrokerControlHandler::new(Arc::new(Mutex::new(agg)), Notifier::new())
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
}
