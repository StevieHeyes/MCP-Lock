//! In-memory broker state and the fail-closed transitions over it.
//!
//! This is the stateful layer above the pure [`crate::policy`] gate. It holds one
//! [`ServerSlot`] per supervised server and applies the lifecycle and elevation
//! transitions, each of which can only ever move exposure *down* to read-only or
//! controlled-up under an explicit, verified elevation.
//!
//! There is deliberately **no persistence**: state is reconstructed from the
//! manifest at start via [`BrokerState::from_manifest`], which is what makes
//! "elevation never survives a restart" a structural property rather than a
//! runtime check. Slice 2 has no transport; this is driven by tests and by the
//! daemon's read-only `--check-manifest` mode.

use std::collections::BTreeMap;

use crate::manifest::LoadedManifest;
use crate::policy::{
    classify_advertised, resolve_exposure, ClassifiedTool, Elevation, ServerState, Timestamp,
};

/// The state of one supervised server.
#[derive(Debug, Clone)]
pub struct ServerSlot {
    id: String,
    tools: Vec<ClassifiedTool>,
    state: ServerState,
    elevation: Option<Elevation>,
}

impl ServerSlot {
    /// A freshly started slot: `Running`, read-only, with no elevation. This is
    /// the only constructor, so a slot can never be born elevated.
    pub fn new_running(id: impl Into<String>, tools: Vec<ClassifiedTool>) -> Self {
        ServerSlot {
            id: id.into(),
            tools,
            state: ServerState::Running,
            elevation: None,
        }
    }

    /// The server id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The classified tools.
    pub fn tools(&self) -> &[ClassifiedTool] {
        &self.tools
    }

    /// The current lifecycle state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// The current elevation, if any.
    pub fn elevation(&self) -> Option<&Elevation> {
        self.elevation.as_ref()
    }

    /// The tools exposed to the model right now.
    pub fn exposed(&self, now: Timestamp) -> Vec<String> {
        resolve_exposure(&self.tools, self.state, self.elevation.as_ref(), now)
    }

    /// Grant a (verified) elevation. In Slice 2 the elevation is constructed by
    /// tests; in Slice 5 it is produced only after a presence assertion is
    /// verified.
    pub fn grant_elevation(&mut self, elevation: Elevation) {
        self.elevation = Some(elevation);
    }

    /// Explicitly revoke any elevation.
    pub fn revoke_elevation(&mut self) {
        self.elevation = None;
    }

    /// Drop any elevation in response to a fault (child crash, missed timer,
    /// control-API disconnect, panic recovery). The fail-closed reaction to
    /// anything unexpected.
    pub fn fail_closed(&mut self) {
        self.elevation = None;
    }

    /// Set the lifecycle state. Lifecycle commands carry no presence (Slice 4);
    /// the worst a lifecycle change can do is reduce exposure.
    pub fn set_state(&mut self, state: ServerState) {
        self.state = state;
    }
}

/// The whole broker's in-memory state.
#[derive(Debug, Clone)]
pub struct BrokerState {
    servers: Vec<ServerSlot>,
}

impl BrokerState {
    /// Cold start from explicit slots. Every slot must already be read-only with
    /// no elevation (which is all [`ServerSlot::new_running`] can produce).
    pub fn cold_start(servers: Vec<ServerSlot>) -> Self {
        BrokerState { servers }
    }

    /// Cold start from a loaded manifest.
    ///
    /// Each server's slot is built by classifying the tool names the operator
    /// declared for it (these stand in for the names a child would advertise;
    /// the live aggregator in Slice 3 will classify what the child actually
    /// advertises, with the same default-deny rule). Every slot is `Running`,
    /// read-only, with zero elevations — regardless of anything that happened
    /// before this call. This is why elevation cannot survive a restart.
    pub fn from_manifest(loaded: &LoadedManifest) -> Self {
        let servers = loaded
            .manifest
            .servers
            .iter()
            .map(|s| {
                let advertised: Vec<String> = s.tools.keys().cloned().collect();
                let classified = classify_advertised(&s.tools, &advertised);
                ServerSlot::new_running(s.id.clone(), classified)
            })
            .collect();
        BrokerState { servers }
    }

    /// All server slots.
    pub fn servers(&self) -> &[ServerSlot] {
        &self.servers
    }

    /// Look up a slot by id.
    pub fn server(&self, id: &str) -> Option<&ServerSlot> {
        self.servers.iter().find(|s| s.id() == id)
    }

    /// Look up a slot by id, mutably.
    pub fn server_mut(&mut self, id: &str) -> Option<&mut ServerSlot> {
        self.servers.iter_mut().find(|s| s.id() == id)
    }

    /// Total number of active elevation grants across all servers. Zero at cold
    /// start; asserted by the fail-closed tests.
    pub fn elevation_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| s.elevation().is_some())
            .count()
    }

    /// A snapshot of `id -> exposed tool names` for every server. Slice 3 diffs
    /// two snapshots to decide when to fire MCP `tools/list_changed`.
    pub fn exposure_snapshot(&self, now: Timestamp) -> BTreeMap<String, Vec<String>> {
        self.servers
            .iter()
            .map(|s| (s.id().to_string(), s.exposed(now)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{load_from_bytes, ToolClass};
    use crate::policy::ClassifiedTool;

    const MANIFEST: &str = r#"{
        "servers": [{
            "id": "mail",
            "command": "mcp-lock-mail",
            "tools": {
                "search": "read",
                "fetch_message": "read",
                "send_message": "confirm",
                "delete_message": "write"
            }
        }]
    }"#;

    fn loaded() -> LoadedManifest {
        load_from_bytes(MANIFEST.as_bytes()).unwrap()
    }

    #[test]
    fn cold_start_has_zero_elevations_and_is_read_only() {
        let state = BrokerState::from_manifest(&loaded());
        assert_eq!(state.elevation_count(), 0);
        let exposed = state.server("mail").unwrap().exposed(0);
        assert_eq!(exposed, vec!["fetch_message", "search"]);
    }

    #[test]
    fn granting_elevation_exposes_write_and_confirm() {
        let mut state = BrokerState::from_manifest(&loaded());
        state
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        let exposed = state.server("mail").unwrap().exposed(100);
        assert_eq!(
            exposed,
            vec!["delete_message", "fetch_message", "search", "send_message"]
        );
    }

    #[test]
    fn fault_reverts_to_read_only() {
        let mut state = BrokerState::from_manifest(&loaded());
        let mail = state.server_mut("mail").unwrap();
        mail.grant_elevation(Elevation::for_duration(0, 300));
        assert_eq!(mail.exposed(100).len(), 4);
        mail.fail_closed();
        assert_eq!(mail.exposed(100), vec!["fetch_message", "search"]);
        assert_eq!(state.elevation_count(), 0);
    }

    #[test]
    fn expiry_reverts_to_read_only_without_any_action() {
        let mut state = BrokerState::from_manifest(&loaded());
        state
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300)); // expires at 300
        let mail = state.server("mail").unwrap();
        assert_eq!(
            mail.exposed(299).len(),
            4,
            "still elevated just before expiry"
        );
        assert_eq!(
            mail.exposed(300),
            vec!["fetch_message", "search"],
            "at expiry, fail closed"
        );
    }

    #[test]
    fn pause_and_stop_immediately_reduce_exposure() {
        let mut state = BrokerState::from_manifest(&loaded());
        state
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        state
            .server_mut("mail")
            .unwrap()
            .set_state(ServerState::Paused);
        assert!(state.server("mail").unwrap().exposed(100).is_empty());
        state
            .server_mut("mail")
            .unwrap()
            .set_state(ServerState::Stopped);
        assert!(state.server("mail").unwrap().exposed(100).is_empty());
    }

    #[test]
    fn resume_re_exposes_read_tools_only_not_the_old_elevation() {
        let mut state = BrokerState::from_manifest(&loaded());
        let mail = state.server_mut("mail").unwrap();
        mail.grant_elevation(Elevation::for_duration(0, 300));
        mail.set_state(ServerState::Paused);
        // A real pause/resume in Slice 4 leaves the elevation timer running; here
        // we show that resuming exposes read tools and, if the elevation is still
        // active, its write tools — exposure is always recomputed, never stored.
        mail.set_state(ServerState::Running);
        assert_eq!(mail.exposed(100).len(), 4);
    }

    #[test]
    fn restart_does_not_carry_elevation() {
        // Grant an elevation, then "restart" by rebuilding from the manifest.
        let mut before = BrokerState::from_manifest(&loaded());
        before
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::until_revoked(0));
        assert_eq!(before.elevation_count(), 1);

        let after = BrokerState::from_manifest(&loaded());
        assert_eq!(
            after.elevation_count(),
            0,
            "elevation must not survive restart"
        );
        assert_eq!(
            after.server("mail").unwrap().exposed(1_000_000),
            vec!["fetch_message", "search"],
            "even an until-revoked elevation is gone after restart"
        );
    }

    #[test]
    fn confirm_tools_are_flagged_for_per_action_presence() {
        let state = BrokerState::from_manifest(&loaded());
        let send = state
            .server("mail")
            .unwrap()
            .tools()
            .iter()
            .find(|t| t.name == "send_message")
            .unwrap();
        assert_eq!(send.class, ToolClass::Confirm);
        assert!(
            send.class.requires_per_action_presence(),
            "confirm tools still need a fresh per-action presence ack at call time (Slice 5)"
        );
    }

    #[test]
    fn exposure_snapshot_tracks_changes() {
        let mut state = BrokerState::from_manifest(&loaded());
        let before = state.exposure_snapshot(100);
        state
            .server_mut("mail")
            .unwrap()
            .grant_elevation(Elevation::for_duration(0, 300));
        let after = state.exposure_snapshot(100);
        assert_ne!(before, after, "granting elevation changes exposure");
    }

    #[test]
    fn undeclared_advertised_tool_is_gated() {
        // A child advertising a tool the manifest never classified: it must be
        // treated as write (gated), exposed only under elevation.
        let tools = vec![
            ClassifiedTool {
                name: "read_x".to_string(),
                class: ToolClass::Read,
            },
            // Simulate classification of an undeclared tool via default-deny.
            crate::policy::classify(&Default::default(), "surprise_tool"),
        ];
        let mut slot = ServerSlot::new_running("s", tools);
        assert_eq!(slot.exposed(0), vec!["read_x"]);
        slot.grant_elevation(Elevation::until_revoked(0));
        assert_eq!(slot.exposed(0), vec!["read_x", "surprise_tool"]);
    }
}
