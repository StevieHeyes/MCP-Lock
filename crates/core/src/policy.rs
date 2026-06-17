//! The exposure-resolution policy: the heart of the system.
//!
//! Given a server's classified tools, its lifecycle state, and its elevation
//! state, this module decides exactly which tools are exposed to the model:
//!
//! ```text
//! exposed = read tools + (write/confirm tools  iff  elevation active & unexpired)
//! ```
//!
//! and only while the server is `Running`. Everything here is pure, synchronous,
//! and free of IO so the fail-closed invariants can be read and tested directly.
//!
//! Two defaults make it fail closed:
//! * **Default-deny classification.** A tool the running child advertises but
//!   that is absent from the operator manifest is classified [`ToolClass::Write`]
//!   — gated — not silently exposed.
//! * **Default-deny exposure.** Absent or expired elevation, or any non-Running
//!   state, yields read-only (or empty) exposure.

use std::collections::BTreeMap;

use crate::manifest::ToolClass;

/// A tool name paired with its resolved (operator-authoritative) classification.
///
/// The only way to obtain one is through [`classify`] / [`classify_advertised`],
/// so a tool is always *classified before it can be considered for exposure*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedTool {
    /// The tool's name as advertised by the child.
    pub name: String,
    /// Its classification, per the manifest (or the default-deny fallback).
    pub class: ToolClass,
}

/// Classify a single advertised tool name against the manifest's tool map.
///
/// A name absent from the manifest is [`ToolClass::Write`] — default-deny. The
/// gated party cannot widen its own surface by advertising a tool the operator
/// never classified.
pub fn classify(
    manifest_tools: &BTreeMap<String, ToolClass>,
    advertised_name: &str,
) -> ClassifiedTool {
    let class = manifest_tools
        .get(advertised_name)
        .copied()
        .unwrap_or(ToolClass::Write);
    ClassifiedTool {
        name: advertised_name.to_string(),
        class,
    }
}

/// Classify every advertised tool name against the manifest's tool map.
pub fn classify_advertised(
    manifest_tools: &BTreeMap<String, ToolClass>,
    advertised: &[String],
) -> Vec<ClassifiedTool> {
    advertised
        .iter()
        .map(|name| classify(manifest_tools, name))
        .collect()
}

/// A monotonic timestamp in whole seconds, supplied by the caller.
///
/// The policy core takes time as an argument rather than reading a clock, so it
/// stays pure and its time-dependent behaviour (expiry) is deterministic in
/// tests. The daemon supplies a real monotonic clock at the edge.
pub type Timestamp = u64;

/// How an elevation ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationMode {
    /// Auto-revokes at a fixed expiry. The default and the safe choice.
    Duration,
    /// Stays active until explicitly revoked. Opt-in and deliberately noisy to
    /// enable (see `docs/DESIGN.md`); still never survives a restart.
    UntilRevoked,
}

/// An active write-elevation for a server.
///
/// Constructed only by the security core when a presence assertion has been
/// verified (Slice 5). It carries its own expiry so exposure resolution cannot
/// forget to check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elevation {
    /// When it was granted.
    pub granted_at: Timestamp,
    /// When it expires; `None` means until-revoked.
    pub expires_at: Option<Timestamp>,
}

impl Elevation {
    /// A time-boxed elevation expiring `ttl_secs` after `granted_at`.
    pub fn for_duration(granted_at: Timestamp, ttl_secs: Timestamp) -> Self {
        Elevation {
            granted_at,
            // Saturate so an absurd ttl cannot wrap to an early/!expiry.
            expires_at: Some(granted_at.saturating_add(ttl_secs)),
        }
    }

    /// An until-revoked elevation (opt-in; no automatic expiry).
    pub fn until_revoked(granted_at: Timestamp) -> Self {
        Elevation {
            granted_at,
            expires_at: None,
        }
    }

    /// The mode this elevation represents.
    pub fn mode(self) -> ElevationMode {
        match self.expires_at {
            Some(_) => ElevationMode::Duration,
            None => ElevationMode::UntilRevoked,
        }
    }

    /// Whether the elevation is active at `now`. A duration elevation is active
    /// strictly before its expiry; at or after expiry it is inactive
    /// (fail-closed at the boundary).
    pub fn is_active(self, now: Timestamp) -> bool {
        match self.expires_at {
            Some(expiry) => now < expiry,
            None => true,
        }
    }
}

/// A server's lifecycle state. Transitions are driven by the CLI in Slice 4;
/// exposure depends on the state now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Spawned and routing; read tools (and, if elevated, write tools) exposed.
    Running,
    /// Process alive but not routing: exposes nothing, resumes instantly.
    Paused,
    /// Not running: exposes nothing.
    Stopped,
}

/// Resolve the exposed tool set for one server.
///
/// Returns the names of the tools currently offered to the model, sorted for a
/// stable, comparable result. Fail-closed throughout: non-Running state exposes
/// nothing; without an active, unexpired elevation only read tools are exposed.
pub fn resolve_exposure(
    tools: &[ClassifiedTool],
    state: ServerState,
    elevation: Option<&Elevation>,
    now: Timestamp,
) -> Vec<String> {
    if state != ServerState::Running {
        return Vec::new();
    }
    let elevated = elevation.is_some_and(|e| e.is_active(now));
    let mut exposed: Vec<String> = tools
        .iter()
        .filter(|t| t.class.is_read() || elevated)
        .map(|t| t.name.clone())
        .collect();
    exposed.sort();
    exposed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<ClassifiedTool> {
        let mut m = BTreeMap::new();
        m.insert("read_a".to_string(), ToolClass::Read);
        m.insert("write_b".to_string(), ToolClass::Write);
        m.insert("send_c".to_string(), ToolClass::Confirm);
        classify_advertised(
            &m,
            &[
                "read_a".to_string(),
                "write_b".to_string(),
                "send_c".to_string(),
                "undeclared_d".to_string(),
            ],
        )
    }

    #[test]
    fn undeclared_tool_defaults_to_write() {
        let classified = tools();
        let d = classified
            .iter()
            .find(|t| t.name == "undeclared_d")
            .unwrap();
        assert_eq!(d.class, ToolClass::Write, "default-deny");
    }

    #[test]
    fn without_elevation_only_read_tools_are_exposed() {
        let exposed = resolve_exposure(&tools(), ServerState::Running, None, 100);
        assert_eq!(exposed, vec!["read_a"]);
    }

    #[test]
    fn active_elevation_exposes_write_and_confirm_too() {
        let elevation = Elevation::for_duration(100, 60);
        let exposed = resolve_exposure(&tools(), ServerState::Running, Some(&elevation), 120);
        // read + write + confirm + the default-deny'd undeclared (now write).
        assert_eq!(exposed, vec!["read_a", "send_c", "undeclared_d", "write_b"]);
    }

    #[test]
    fn expired_elevation_falls_back_to_read_only() {
        let elevation = Elevation::for_duration(100, 60); // expires at 160
        let exposed = resolve_exposure(&tools(), ServerState::Running, Some(&elevation), 160);
        assert_eq!(exposed, vec!["read_a"], "at expiry boundary, fail closed");
        let later = resolve_exposure(&tools(), ServerState::Running, Some(&elevation), 9999);
        assert_eq!(later, vec!["read_a"]);
    }

    #[test]
    fn paused_and_stopped_expose_nothing_even_when_elevated() {
        let elevation = Elevation::for_duration(100, 600);
        for state in [ServerState::Paused, ServerState::Stopped] {
            let exposed = resolve_exposure(&tools(), state, Some(&elevation), 120);
            assert!(exposed.is_empty(), "{state:?} must expose nothing");
        }
    }

    #[test]
    fn until_revoked_is_active_until_revoked() {
        let elevation = Elevation::until_revoked(100);
        assert!(elevation.is_active(1_000_000));
        assert_eq!(elevation.mode(), ElevationMode::UntilRevoked);
    }

    #[test]
    fn duration_saturates_and_stays_bounded() {
        let elevation = Elevation::for_duration(10, Timestamp::MAX);
        assert_eq!(elevation.expires_at, Some(Timestamp::MAX));
        assert_eq!(elevation.mode(), ElevationMode::Duration);
    }
}
