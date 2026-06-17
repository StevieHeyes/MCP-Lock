//! The fail-closed invariants from `docs/DESIGN.md` ("Fail-closed invariants —
//! encode as tests"), as first-class, public-API tests. Each test names the
//! invariant it pins. If one of these ever fails, a security property has
//! regressed.

use mcp_lock_core::broker::BrokerState;
use mcp_lock_core::manifest::load_from_bytes;
use mcp_lock_core::policy::{Elevation, ServerState};

const MANIFEST: &[u8] = br#"{
    "servers": [{
        "id": "mail",
        "command": "mcp-lock-mail",
        "tools": {
            "search": "read",
            "list_messages": "read",
            "fetch_message": "read",
            "send_message": "confirm",
            "delete_message": "write"
        }
    }]
}"#;

fn fresh() -> BrokerState {
    BrokerState::from_manifest(&load_from_bytes(MANIFEST).unwrap())
}

const READ_ONLY: [&str; 3] = ["fetch_message", "list_messages", "search"];

/// "Cold start: every server read-only, zero elevations, regardless of prior
/// state."
#[test]
fn cold_start_is_read_only_with_zero_elevations() {
    let state = fresh();
    assert_eq!(state.elevation_count(), 0);
    assert_eq!(state.server("mail").unwrap().exposed(0), READ_ONLY);
}

/// "Elevation NEVER persists across broker restart."
#[test]
fn elevation_never_survives_restart() {
    let mut before = fresh();
    before
        .server_mut("mail")
        .unwrap()
        .grant_elevation(Elevation::until_revoked(0)); // strongest: no expiry
    assert_eq!(before.elevation_count(), 1);

    // A restart is just rebuilding from the manifest. There is no persistence
    // path for elevation, so it cannot come back.
    let after = fresh();
    assert_eq!(after.elevation_count(), 0);
    assert_eq!(after.server("mail").unwrap().exposed(u64::MAX), READ_ONLY);
}

/// "Any fault (child crash, missed timer, control-API disconnect, panic): revert
/// to read-only."
#[test]
fn any_fault_reverts_to_read_only() {
    let mut state = fresh();
    let mail = state.server_mut("mail").unwrap();
    mail.grant_elevation(Elevation::for_duration(0, 600));
    assert_eq!(
        mail.exposed(1).len(),
        5,
        "elevated exposes write+confirm too"
    );
    mail.fail_closed();
    assert_eq!(mail.exposed(1), READ_ONLY);
}

/// "pause and stop immediately recompute exposure downward."
#[test]
fn pause_and_stop_recompute_exposure_downward() {
    let mut state = fresh();
    state
        .server_mut("mail")
        .unwrap()
        .grant_elevation(Elevation::for_duration(0, 600));
    for down in [ServerState::Paused, ServerState::Stopped] {
        state.server_mut("mail").unwrap().set_state(down);
        assert!(
            state.server("mail").unwrap().exposed(1).is_empty(),
            "{down:?} must expose nothing"
        );
    }
}

/// Time-boxing: a duration elevation reverts to read-only at expiry with no
/// action taken (the boundary is fail-closed).
#[test]
fn elevation_expiry_is_fail_closed_at_the_boundary() {
    let mut state = fresh();
    state
        .server_mut("mail")
        .unwrap()
        .grant_elevation(Elevation::for_duration(100, 60)); // expires at 160
    let mail = state.server("mail").unwrap();
    assert_eq!(mail.exposed(159).len(), 5, "active just before expiry");
    assert_eq!(mail.exposed(160), READ_ONLY, "inactive at expiry");
}

/// "confirmTools actions require a fresh presence ack even mid-elevation." Slice
/// 2 records the requirement on the classification; the call-time gate is Slice
/// 5. Here we pin that a confirm tool is both exposed under elevation AND flagged
/// as needing per-action presence.
#[test]
fn confirm_tools_are_flagged_even_when_exposed() {
    let mut state = fresh();
    state
        .server_mut("mail")
        .unwrap()
        .grant_elevation(Elevation::for_duration(0, 600));
    let mail = state.server("mail").unwrap();
    assert!(mail.exposed(1).contains(&"send_message".to_string()));
    let send = mail
        .tools()
        .iter()
        .find(|t| t.name == "send_message")
        .unwrap();
    assert!(send.class.requires_per_action_presence());
}

/// "First run is CLOSED: ... privileged actions refused until [registration]."
/// Modelled here as: a fresh state grants no write exposure to anyone until an
/// elevation is explicitly granted — there is no default-on privilege.
#[test]
fn first_run_ships_closed() {
    let state = fresh();
    let exposed = state.server("mail").unwrap().exposed(0);
    assert!(!exposed.contains(&"send_message".to_string()));
    assert!(!exposed.contains(&"delete_message".to_string()));
    assert_eq!(exposed, READ_ONLY);
}
