//! The tool aggregator: the broker's mediation between the upstream MCP client
//! and the supervised child servers.
//!
//! It combines the supervised children with the security-core exposure gate:
//! * at build time it discovers each child's advertised tools and classifies
//!   them against the operator manifest (default-deny via `mcp_lock_core`);
//! * `aggregated_tools` returns only the tools policy currently exposes, with
//!   each renamed to `"{server_id}.{tool}"` so names never collide;
//! * `call` re-checks the exposure gate before routing — the listing is the
//!   primary gate, this call-time check is defence in depth.
//!
//! Lifecycle/elevation mutation goes through [`Aggregator::state_mut`]; callers
//! detect whether the exposed set changed (to fire `tools/list_changed`) by
//! diffing [`Aggregator::exposure_snapshot`] across the change.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Value};

use mcp_lock_core::broker::{BrokerState, ServerSlot};
use mcp_lock_core::manifest::{LoadedManifest, ServerManifest, ToolClass};
use mcp_lock_core::policy::{classify_advertised, ClassifiedTool, ServerState, Timestamp};

use crate::mcp_client::{ChildError, McpChild};

/// Separator between server id and tool name in an aggregated tool name.
pub const NAMESPACE_SEP: char = '.';

/// How long a per-action confirmation remains usable after it is approved
/// (seconds). Short: a confirm authorises one imminent action, not a window.
pub const CONFIRMATION_TTL_SECS: u64 = 30;

/// A single-use approval for a `confirm`-classified tool action.
struct Confirmation {
    server_id: String,
    tool: String,
    approved_at: Timestamp,
}

/// A function that spawns a child for a given server. Stored so a stopped server
/// can be re-spawned by [`Aggregator::start`].
type Spawner = Box<dyn FnMut(&ServerManifest) -> Result<Box<dyn McpChild>, ChildError> + Send>;

/// A freshly spawned child plus its classified tools and raw tool definitions.
type SpawnedServer = (
    Box<dyn McpChild>,
    Vec<ClassifiedTool>,
    BTreeMap<String, Value>,
);

/// Errors from aggregator operations.
#[derive(Debug)]
pub enum AggregatorError {
    /// A manifest server id contains the namespace separator, which would make
    /// routing ambiguous.
    InvalidServerId(String),
    /// No server with the given id exists in the manifest.
    UnknownServer(String),
    /// The requested external tool name does not resolve to a known tool.
    UnknownTool(String),
    /// The tool exists but is not currently exposed (gated by policy).
    NotExposed(String),
    /// A `confirm`-classified tool was called without a fresh per-action
    /// confirmation.
    NotConfirmed(String),
    /// The underlying child failed.
    Child(ChildError),
}

impl fmt::Display for AggregatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AggregatorError::InvalidServerId(id) => {
                write!(f, "server id '{id}' must not contain '{NAMESPACE_SEP}'")
            }
            AggregatorError::UnknownServer(id) => write!(f, "unknown server: {id}"),
            AggregatorError::UnknownTool(name) => write!(f, "unknown tool: {name}"),
            AggregatorError::NotExposed(name) => {
                write!(f, "tool not currently exposed: {name}")
            }
            AggregatorError::NotConfirmed(name) => {
                write!(f, "tool requires a fresh per-action confirmation: {name}")
            }
            AggregatorError::Child(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AggregatorError {}

/// Build a fail-closed (`Stopped`) slot for `server`, classifying its declared
/// tools against `advertised`. Used when a child can't spawn or list tools at
/// build time: the slot exists (so lifecycle/restart can act on it) but exposes
/// nothing while it is `Stopped`.
fn stopped_slot(server: &ServerManifest, advertised: &[String]) -> ServerSlot {
    let classified = classify_advertised(&server.tools, advertised);
    let mut slot = ServerSlot::new_running(server.id.clone(), classified);
    slot.set_state(ServerState::Stopped);
    slot
}

/// The broker's aggregated view over its supervised children.
pub struct Aggregator {
    /// The manifest, retained so a stopped server can be re-spawned.
    manifest: LoadedManifest,
    /// How to spawn a child, retained for [`Aggregator::start`].
    spawner: Spawner,
    state: BrokerState,
    children: BTreeMap<String, Box<dyn McpChild>>,
    /// server id -> (tool name -> full tool definition from the child).
    tool_defs: BTreeMap<String, BTreeMap<String, Value>>,
    /// Outstanding single-use per-action confirmations for `confirm` tools.
    confirmations: Vec<Confirmation>,
}

// Hand-written: the trait objects in `children` are not Debug.
impl fmt::Debug for Aggregator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aggregator")
            .field("servers", &self.state.servers().len())
            .finish()
    }
}

impl Aggregator {
    /// Build an aggregator from a manifest, obtaining each child via `spawn`.
    ///
    /// `spawn` is injected so the real path spawns [`crate::mcp_client::StdioMcpClient`]
    /// while tests pass in-process fakes. For each server we obtain the child,
    /// list its tools, classify them against the manifest (default-deny), and
    /// build a cold-start (read-only, zero-elevation) slot.
    pub fn build<F>(loaded: &LoadedManifest, spawn: F) -> Result<Self, AggregatorError>
    where
        F: FnMut(&ServerManifest) -> Result<Box<dyn McpChild>, ChildError> + Send + 'static,
    {
        let mut spawner: Spawner = Box::new(spawn);
        let mut children: BTreeMap<String, Box<dyn McpChild>> = BTreeMap::new();
        let mut tool_defs: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        let mut slots: Vec<ServerSlot> = Vec::new();

        for server in &loaded.manifest.servers {
            if server.id.contains(NAMESPACE_SEP) {
                // A manifest defect, not a runtime fault: fail the whole build
                // so the operator fixes it, rather than silently degrading.
                return Err(AggregatorError::InvalidServerId(server.id.clone()));
            }
            // A single child failing to spawn or list tools must not take down
            // the whole broker: degrade that one server to a `Stopped`
            // (fail-closed, exposes nothing) slot and keep going, so a healthy
            // server still comes up. A later `start` can respawn it via the
            // retained spawner. (An `InvalidServerId` above is different: that's
            // a manifest defect the operator must fix, so it fails the build.)
            match spawn_and_classify(&mut spawner, server) {
                Ok((child, classified, defs)) => {
                    slots.push(ServerSlot::new_running(server.id.clone(), classified));
                    tool_defs.insert(server.id.clone(), defs);
                    children.insert(server.id.clone(), child);
                }
                Err(AggregatorError::Child(e)) => {
                    eprintln!(
                        "mcp-lockd: server '{}' failed to start ({e}); starting it stopped \
                         (no tools exposed)",
                        server.id
                    );
                    slots.push(stopped_slot(server, &[]));
                    tool_defs.insert(server.id.clone(), BTreeMap::new());
                }
                Err(other) => return Err(other),
            }
        }

        Ok(Aggregator {
            manifest: loaded.clone(),
            spawner,
            state: BrokerState::cold_start(slots),
            children,
            tool_defs,
            confirmations: Vec::new(),
        })
    }

    /// The classification of a tool, if the server and tool are known.
    pub fn tool_class(&self, server_id: &str, tool: &str) -> Option<ToolClass> {
        self.state
            .server(server_id)?
            .tools()
            .iter()
            .find(|t| t.name == tool)
            .map(|t| t.class)
    }

    /// Record a verified per-action confirmation for a `confirm` tool. The next
    /// call to that tool within [`CONFIRMATION_TTL_SECS`] consumes it.
    pub fn approve_action(&mut self, server_id: &str, tool: &str, now: Timestamp) {
        self.confirmations.retain(|c| !confirmation_expired(c, now));
        self.confirmations.push(Confirmation {
            server_id: server_id.to_string(),
            tool: tool.to_string(),
            approved_at: now,
        });
    }

    /// Pause a server: routing-level only (the process keeps running, so resume
    /// is instant). Exposes nothing while paused. Returns the unknown-server
    /// error if `id` is not in the manifest.
    pub fn pause(&mut self, id: &str) -> Result<(), AggregatorError> {
        self.set_state(id, ServerState::Paused)
    }

    /// Resume a paused server, re-exposing its (policy-gated) tools.
    pub fn resume(&mut self, id: &str) -> Result<(), AggregatorError> {
        self.set_state(id, ServerState::Running)
    }

    /// Stop a server: mark it stopped (exposes nothing) and terminate its child
    /// process (the child is dropped, which kills it). Idempotent.
    pub fn stop(&mut self, id: &str) -> Result<(), AggregatorError> {
        self.set_state(id, ServerState::Stopped)?;
        // Dropping the child handle terminates the process (see StdioMcpClient::drop).
        self.children.remove(id);
        Ok(())
    }

    /// Start (or restart) a server: spawn it if no child is running, re-discover
    /// and re-classify its tools, and set it Running. Brings a server up
    /// read-only — never elevated.
    pub fn start(&mut self, id: &str) -> Result<(), AggregatorError> {
        let server = self
            .manifest
            .manifest
            .server(id)
            .cloned()
            .ok_or_else(|| AggregatorError::UnknownServer(id.to_string()))?;

        if !self.children.contains_key(id) {
            let (child, classified, defs) = spawn_and_classify(&mut self.spawner, &server)?;
            self.children.insert(id.to_string(), child);
            self.tool_defs.insert(id.to_string(), defs);
            if let Some(slot) = self.state.server_mut(id) {
                slot.set_tools(classified);
            }
        }
        self.set_state(id, ServerState::Running)
    }

    fn set_state(&mut self, id: &str, state: ServerState) -> Result<(), AggregatorError> {
        let slot = self
            .state
            .server_mut(id)
            .ok_or_else(|| AggregatorError::UnknownServer(id.to_string()))?;
        slot.set_state(state);
        Ok(())
    }

    /// The MCP `tools/list` payload at `now`: every currently-exposed tool,
    /// renamed to `"{server_id}.{tool}"`. Tools the policy gates are absent.
    pub fn aggregated_tools(&self, now: Timestamp) -> Vec<Value> {
        let mut out = Vec::new();
        for slot in self.state.servers() {
            let Some(defs) = self.tool_defs.get(slot.id()) else {
                continue;
            };
            for tool_name in slot.exposed(now) {
                if let Some(def) = defs.get(&tool_name) {
                    let mut def = def.clone();
                    if let Some(obj) = def.as_object_mut() {
                        obj.insert(
                            "name".to_string(),
                            json!(format!("{}{}{}", slot.id(), NAMESPACE_SEP, tool_name)),
                        );
                    }
                    out.push(def);
                }
            }
        }
        out
    }

    /// Route a `tools/call` for an aggregated (namespaced) tool name.
    ///
    /// Re-checks the exposure gate: a tool that is not currently exposed is
    /// rejected even if the caller somehow named it. This is the call-time
    /// fallback behind the primary listing gate.
    pub fn call(
        &mut self,
        external_name: &str,
        arguments: Value,
        now: Timestamp,
    ) -> Result<Value, AggregatorError> {
        let (server_id, tool) = external_name
            .split_once(NAMESPACE_SEP)
            .ok_or_else(|| AggregatorError::UnknownTool(external_name.to_string()))?;

        // Read what we need from the slot, then drop the borrow.
        let (exposed, class) = {
            let slot = self
                .state
                .server(server_id)
                .ok_or_else(|| AggregatorError::UnknownTool(external_name.to_string()))?;
            let exposed = slot.exposed(now);
            let class = slot
                .tools()
                .iter()
                .find(|t| t.name == tool)
                .map(|t| t.class);
            (exposed, class)
        };

        if !exposed.iter().any(|t| t == tool) {
            return Err(AggregatorError::NotExposed(external_name.to_string()));
        }

        // A confirm-classified tool needs a fresh, single-use per-action
        // confirmation, even while elevated. The model cannot supply one, so
        // these stay closed unless an operator has just approved this exact tool.
        if matches!(class, Some(c) if c.requires_per_action_presence()) {
            let position = self.confirmations.iter().position(|c| {
                c.server_id == server_id && c.tool == tool && !confirmation_expired(c, now)
            });
            match position {
                Some(i) => {
                    self.confirmations.swap_remove(i);
                }
                None => return Err(AggregatorError::NotConfirmed(external_name.to_string())),
            }
        }

        let child = self
            .children
            .get_mut(server_id)
            .ok_or_else(|| AggregatorError::UnknownTool(external_name.to_string()))?;
        match child.call_tool(tool, arguments) {
            Ok(value) => Ok(value),
            Err(e) => {
                // A crashed (`Exited`/`Io`) or hung (`Timeout`) child must fail
                // closed immediately: stop exposing its tools and drop any
                // elevation BEFORE the error propagates, so the very next
                // listing reflects the fault. An `Rpc`/`Protocol` error is the
                // child answering — it stays up.
                if matches!(
                    e,
                    ChildError::Exited | ChildError::Io(_) | ChildError::Timeout
                ) {
                    if let Some(slot) = self.state.server_mut(server_id) {
                        slot.set_state(ServerState::Stopped);
                        slot.fail_closed();
                    }
                }
                Err(AggregatorError::Child(e))
            }
        }
    }

    /// Fail closed any child that has died since we last looked. A supervising
    /// handler calls this before computing the exposed listing so a child that
    /// crashed between calls has its tools dropped and its elevation revoked.
    ///
    /// For each child, if it is not alive, its slot is moved to `Stopped` and
    /// `fail_closed()`; live children are left untouched. Idempotent.
    pub fn reap_exited_children(&mut self) {
        for (id, child) in self.children.iter_mut() {
            if !child.is_alive() {
                if let Some(slot) = self.state.server_mut(id) {
                    slot.set_state(ServerState::Stopped);
                    slot.fail_closed();
                }
            }
        }
    }

    /// Shared access to the broker state (read).
    pub fn state(&self) -> &BrokerState {
        &self.state
    }

    /// Mutable access to the broker state, for lifecycle/elevation transitions.
    pub fn state_mut(&mut self) -> &mut BrokerState {
        &mut self.state
    }

    /// A snapshot of the currently-exposed (namespaced) tool names per server.
    /// Diff two snapshots across a transition to decide whether to fire
    /// `tools/list_changed`.
    pub fn exposure_snapshot(&self, now: Timestamp) -> BTreeMap<String, Vec<String>> {
        self.state.exposure_snapshot(now)
    }
}

fn confirmation_expired(c: &Confirmation, now: Timestamp) -> bool {
    now.saturating_sub(c.approved_at) > CONFIRMATION_TTL_SECS
}

/// Spawn a child for `server`, list its tools, and classify them against the
/// manifest (default-deny). Shared by build and start.
fn spawn_and_classify(
    spawner: &mut Spawner,
    server: &ServerManifest,
) -> Result<SpawnedServer, AggregatorError> {
    let mut child = spawner(server).map_err(AggregatorError::Child)?;
    let advertised_defs = child.list_tools().map_err(AggregatorError::Child)?;
    let advertised_names: Vec<String> = advertised_defs.iter().map(|t| t.name.clone()).collect();
    let classified = classify_advertised(&server.tools, &advertised_names);
    let defs: BTreeMap<String, Value> = advertised_defs
        .into_iter()
        .map(|t| (t.name, t.definition))
        .collect();
    Ok((child, classified, defs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_lock_core::manifest::load_from_bytes;
    use mcp_lock_core::policy::Elevation;

    use crate::mcp_client::ToolDef;

    /// An in-process fake child with fixed tools that echoes calls back.
    ///
    /// Configurable for the fault paths: `call_error` makes `call_tool` fail
    /// with a chosen error, and `alive` controls what `is_alive` reports.
    struct FakeChild {
        tools: Vec<ToolDef>,
        /// If set, `call_tool` returns this error instead of echoing.
        call_error: Option<ChildError>,
        /// What `is_alive` reports (children are alive by default).
        alive: bool,
    }

    impl FakeChild {
        fn with_tools(names: &[&str]) -> Self {
            let tools = names
                .iter()
                .map(|n| ToolDef {
                    name: (*n).to_string(),
                    definition: json!({ "name": n, "description": format!("tool {n}") }),
                })
                .collect();
            FakeChild {
                tools,
                call_error: None,
                alive: true,
            }
        }

        /// Make `call_tool` fail with `error`.
        fn failing(mut self, error: ChildError) -> Self {
            self.call_error = Some(error);
            self
        }

        /// Make `is_alive` report `false` (the child has died).
        fn dead(mut self) -> Self {
            self.alive = false;
            self
        }
    }

    impl McpChild for FakeChild {
        fn list_tools(&mut self) -> Result<Vec<ToolDef>, ChildError> {
            Ok(self.tools.clone())
        }
        fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, ChildError> {
            if let Some(err) = self.call_error.take() {
                return Err(err);
            }
            Ok(json!({ "called": name, "arguments": arguments }))
        }
        fn is_alive(&mut self) -> bool {
            self.alive
        }
    }

    const MANIFEST: &[u8] = br#"{
        "servers": [{
            "id": "mail",
            "command": "mcp-lock-mail",
            "tools": {
                "search": "read",
                "fetch_message": "read",
                "delete_message": "write"
            }
        }]
    }"#;

    fn build_with_fake() -> Aggregator {
        let loaded = load_from_bytes(MANIFEST).unwrap();
        Aggregator::build(&loaded, |_server| {
            Ok(Box::new(FakeChild::with_tools(&[
                "search",
                "fetch_message",
                "delete_message",
                "undeclared",
            ])) as Box<dyn McpChild>)
        })
        .unwrap()
    }

    fn names(tools: &[Value]) -> Vec<String> {
        let mut n: Vec<String> = tools
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        n.sort();
        n
    }

    #[test]
    fn aggregated_tools_are_namespaced_and_read_only_by_default() {
        let agg = build_with_fake();
        // Only read tools, namespaced. delete_message (write) and undeclared
        // (default-deny write) are gated out.
        assert_eq!(
            names(&agg.aggregated_tools(0)),
            vec!["mail.fetch_message", "mail.search"]
        );
    }

    #[test]
    fn elevation_exposes_write_and_default_denied_tools() {
        let mut agg = build_with_fake();
        agg.state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        assert_eq!(
            names(&agg.aggregated_tools(10)),
            vec![
                "mail.delete_message",
                "mail.fetch_message",
                "mail.search",
                "mail.undeclared"
            ]
        );
    }

    #[test]
    fn call_routes_to_child_for_exposed_tool() {
        let mut agg = build_with_fake();
        let result = agg.call("mail.search", json!({"query": "hi"}), 0).unwrap();
        assert_eq!(result["called"], "search");
        assert_eq!(result["arguments"]["query"], "hi");
    }

    #[test]
    fn call_to_gated_tool_is_rejected_until_elevated() {
        let mut agg = build_with_fake();
        // delete_message is write-class: not exposed, so the call is refused.
        assert!(matches!(
            agg.call("mail.delete_message", json!({}), 0),
            Err(AggregatorError::NotExposed(_))
        ));
        // After elevation it routes.
        agg.state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        assert!(agg.call("mail.delete_message", json!({}), 10).is_ok());
    }

    #[test]
    fn call_to_unknown_tool_or_server_is_unknown() {
        let mut agg = build_with_fake();
        assert!(matches!(
            agg.call("no_separator", json!({}), 0),
            Err(AggregatorError::UnknownTool(_))
        ));
        assert!(matches!(
            agg.call("other.search", json!({}), 0),
            Err(AggregatorError::UnknownTool(_))
        ));
    }

    #[test]
    fn exposure_snapshot_changes_signal_list_changed() {
        let mut agg = build_with_fake();
        let before = agg.exposure_snapshot(0);
        agg.state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        let after = agg.exposure_snapshot(0);
        assert_ne!(before, after);
    }

    #[test]
    fn server_id_with_separator_is_rejected() {
        let bad = br#"{"servers":[{"id":"a.b","command":"x"}]}"#;
        let loaded = load_from_bytes(bad).unwrap();
        let result = Aggregator::build(&loaded, |_| {
            Ok(Box::new(FakeChild::with_tools(&[])) as Box<dyn McpChild>)
        });
        assert!(matches!(result, Err(AggregatorError::InvalidServerId(_))));
    }

    #[test]
    fn call_to_crashed_child_fails_the_server_closed() {
        let loaded = load_from_bytes(MANIFEST).unwrap();
        let mut agg = Aggregator::build(&loaded, |_server| {
            Ok(Box::new(
                FakeChild::with_tools(&["search", "fetch_message", "delete_message"])
                    .failing(ChildError::Exited),
            ) as Box<dyn McpChild>)
        })
        .unwrap();

        // Elevate, so we can prove the elevation is dropped by the fault.
        agg.state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        assert_eq!(agg.state().elevation_count(), 1);

        // The call hits a child that reports `Exited`.
        let result = agg.call("mail.search", json!({}), 0);
        assert!(matches!(
            result,
            Err(AggregatorError::Child(ChildError::Exited))
        ));

        // Fail closed: the slot is Stopped, elevation is gone, nothing exposed.
        let slot = agg.state().server("mail").unwrap();
        assert_eq!(slot.state(), ServerState::Stopped);
        assert_eq!(agg.state().elevation_count(), 0);
        assert!(agg.aggregated_tools(0).is_empty());
    }

    #[test]
    fn reap_exited_children_fails_dead_children_closed() {
        let loaded = load_from_bytes(MANIFEST).unwrap();
        let mut agg = Aggregator::build(&loaded, |_server| {
            Ok(
                Box::new(FakeChild::with_tools(&["search", "fetch_message"]).dead())
                    as Box<dyn McpChild>,
            )
        })
        .unwrap();

        // Healthy at build time, even though the fake reports not-alive.
        agg.state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        assert!(!agg.aggregated_tools(0).is_empty());

        agg.reap_exited_children();

        let slot = agg.state().server("mail").unwrap();
        assert_eq!(slot.state(), ServerState::Stopped);
        assert_eq!(agg.state().elevation_count(), 0);
        assert!(agg.aggregated_tools(0).is_empty());
    }

    #[test]
    fn build_degrades_one_failed_spawn_and_keeps_healthy_servers() {
        // Two servers: `mail` fails to spawn, `cal` comes up healthy.
        let manifest = br#"{
            "servers": [
                {
                    "id": "mail",
                    "command": "mcp-lock-mail",
                    "tools": { "search": "read", "delete_message": "write" }
                },
                {
                    "id": "cal",
                    "command": "mcp-lock-cal",
                    "tools": { "list_events": "read", "create_event": "write" }
                }
            ]
        }"#;
        let loaded = load_from_bytes(manifest).unwrap();

        let agg = Aggregator::build(&loaded, |server| {
            if server.id == "mail" {
                // Simulate a child that cannot be launched.
                Err(ChildError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such binary",
                )))
            } else {
                Ok(
                    Box::new(FakeChild::with_tools(&["list_events", "create_event"]))
                        as Box<dyn McpChild>,
                )
            }
        })
        .expect("a single failed spawn must not abort the whole build");

        // The failed server exists but is Stopped and exposes nothing.
        let mail = agg.state().server("mail").unwrap();
        assert_eq!(mail.state(), ServerState::Stopped);

        // The healthy server still exposes its read tools.
        assert_eq!(names(&agg.aggregated_tools(0)), vec!["cal.list_events"]);
    }

    #[test]
    fn build_keeps_invalid_server_id_a_hard_error() {
        // A manifest defect stays fatal even with the degrade-on-fault change.
        let bad = br#"{"servers":[{"id":"a.b","command":"x"}]}"#;
        let loaded = load_from_bytes(bad).unwrap();
        let result = Aggregator::build(&loaded, |_| {
            Ok(Box::new(FakeChild::with_tools(&[])) as Box<dyn McpChild>)
        });
        assert!(matches!(result, Err(AggregatorError::InvalidServerId(_))));
    }

    #[test]
    fn pause_hides_tools_and_resume_restores() {
        let mut agg = build_with_fake();
        assert!(!agg.aggregated_tools(0).is_empty());
        agg.pause("mail").unwrap();
        assert!(agg.aggregated_tools(0).is_empty(), "paused exposes nothing");
        agg.resume("mail").unwrap();
        assert_eq!(
            names(&agg.aggregated_tools(0)),
            vec!["mail.fetch_message", "mail.search"]
        );
    }

    #[test]
    fn stop_then_start_respawns_read_only() {
        let mut agg = build_with_fake();
        agg.stop("mail").unwrap();
        assert!(
            agg.aggregated_tools(0).is_empty(),
            "stopped exposes nothing"
        );
        // start re-spawns via the retained spawner and comes up read-only.
        agg.start("mail").unwrap();
        assert_eq!(
            names(&agg.aggregated_tools(0)),
            vec!["mail.fetch_message", "mail.search"]
        );
    }

    #[test]
    fn confirm_tool_requires_fresh_approval_even_when_elevated() {
        let manifest = br#"{"servers":[{"id":"mail","command":"x","tools":{"send":"confirm"}}]}"#;
        let loaded = load_from_bytes(manifest).unwrap();
        let mut agg = Aggregator::build(&loaded, |_| {
            Ok(Box::new(FakeChild::with_tools(&["send"])) as Box<dyn McpChild>)
        })
        .unwrap();
        // Elevate so the confirm tool is exposed.
        agg.state_mut()
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::until_revoked(0));
        // Exposed, but no fresh confirmation -> rejected.
        assert!(matches!(
            agg.call("mail.send", json!({}), 0),
            Err(AggregatorError::NotConfirmed(_))
        ));
        // Approve, then exactly one call goes through.
        agg.approve_action("mail", "send", 0);
        assert!(agg.call("mail.send", json!({}), 0).is_ok());
        // Single-use: the next call needs a fresh approval.
        assert!(matches!(
            agg.call("mail.send", json!({}), 0),
            Err(AggregatorError::NotConfirmed(_))
        ));
    }

    #[test]
    fn lifecycle_on_unknown_server_errors() {
        let mut agg = build_with_fake();
        assert!(matches!(
            agg.pause("nope"),
            Err(AggregatorError::UnknownServer(_))
        ));
        assert!(matches!(
            agg.start("nope"),
            Err(AggregatorError::UnknownServer(_))
        ));
    }
}
