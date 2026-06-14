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
use mcp_lock_core::manifest::{LoadedManifest, ServerManifest};
use mcp_lock_core::policy::{classify_advertised, Timestamp};

use crate::mcp_client::{ChildError, McpChild};

/// Separator between server id and tool name in an aggregated tool name.
pub const NAMESPACE_SEP: char = '.';

/// Errors from aggregator operations.
#[derive(Debug)]
pub enum AggregatorError {
    /// A manifest server id contains the namespace separator, which would make
    /// routing ambiguous.
    InvalidServerId(String),
    /// The requested external tool name does not resolve to a known tool.
    UnknownTool(String),
    /// The tool exists but is not currently exposed (gated by policy).
    NotExposed(String),
    /// The underlying child failed.
    Child(ChildError),
}

impl fmt::Display for AggregatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AggregatorError::InvalidServerId(id) => {
                write!(f, "server id '{id}' must not contain '{NAMESPACE_SEP}'")
            }
            AggregatorError::UnknownTool(name) => write!(f, "unknown tool: {name}"),
            AggregatorError::NotExposed(name) => {
                write!(f, "tool not currently exposed: {name}")
            }
            AggregatorError::Child(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AggregatorError {}

/// The broker's aggregated view over its supervised children.
pub struct Aggregator {
    state: BrokerState,
    children: BTreeMap<String, Box<dyn McpChild>>,
    /// server id -> (tool name -> full tool definition from the child).
    tool_defs: BTreeMap<String, BTreeMap<String, Value>>,
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
    pub fn build<F>(loaded: &LoadedManifest, mut spawn: F) -> Result<Self, AggregatorError>
    where
        F: FnMut(&ServerManifest) -> Result<Box<dyn McpChild>, ChildError>,
    {
        let mut children: BTreeMap<String, Box<dyn McpChild>> = BTreeMap::new();
        let mut tool_defs: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        let mut slots: Vec<ServerSlot> = Vec::new();

        for server in &loaded.manifest.servers {
            if server.id.contains(NAMESPACE_SEP) {
                return Err(AggregatorError::InvalidServerId(server.id.clone()));
            }

            let mut child = spawn(server).map_err(AggregatorError::Child)?;
            let advertised_defs = child.list_tools().map_err(AggregatorError::Child)?;

            let advertised_names: Vec<String> =
                advertised_defs.iter().map(|t| t.name.clone()).collect();
            let classified = classify_advertised(&server.tools, &advertised_names);
            slots.push(ServerSlot::new_running(server.id.clone(), classified));

            let defs: BTreeMap<String, Value> = advertised_defs
                .into_iter()
                .map(|t| (t.name, t.definition))
                .collect();
            tool_defs.insert(server.id.clone(), defs);
            children.insert(server.id.clone(), child);
        }

        Ok(Aggregator {
            state: BrokerState::cold_start(slots),
            children,
            tool_defs,
        })
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

        let slot = self
            .state
            .server(server_id)
            .ok_or_else(|| AggregatorError::UnknownTool(external_name.to_string()))?;

        if !slot.exposed(now).iter().any(|t| t == tool) {
            return Err(AggregatorError::NotExposed(external_name.to_string()));
        }

        let child = self
            .children
            .get_mut(server_id)
            .ok_or_else(|| AggregatorError::UnknownTool(external_name.to_string()))?;
        child
            .call_tool(tool, arguments)
            .map_err(AggregatorError::Child)
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

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_lock_core::manifest::load_from_bytes;
    use mcp_lock_core::policy::Elevation;

    use crate::mcp_client::ToolDef;

    /// An in-process fake child with fixed tools that echoes calls back.
    struct FakeChild {
        tools: Vec<ToolDef>,
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
            FakeChild { tools }
        }
    }

    impl McpChild for FakeChild {
        fn list_tools(&mut self) -> Result<Vec<ToolDef>, ChildError> {
            Ok(self.tools.clone())
        }
        fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, ChildError> {
            Ok(json!({ "called": name, "arguments": arguments }))
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
}
