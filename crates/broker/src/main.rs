//! `mcp-lockd` — the MCP-Lock broker daemon.
//!
//! In Slice 0 this is scaffolding: it starts, reports its fail-closed posture,
//! and exits. It supervises no servers and opens no listeners yet. The broker
//! core (manifest, classification, exposure resolution) lands in Slice 2; the
//! aggregator and MCP endpoint in Slice 3; the control channel and elevation in
//! Slice 5.
//!
//! The one real thing it demonstrates now is the v1 execution-context posture
//! every child will eventually be spawned with: first-party, broker identity,
//! no sandbox (see `mcp_lock_core::exec`).

use mcp_lock_core::exec::ExecutionContext;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    // The default child execution context for v1. Nothing is spawned yet; this
    // exercises the seam and states the posture out loud.
    let default_ctx = ExecutionContext::first_party(Vec::new());

    println!("mcp-lockd {VERSION} (scaffolding)");
    println!("state: fail-closed — no servers supervised, no tools exposed, zero elevations");
    println!(
        "child execution context: identity={:?}, sandboxed={}",
        default_ctx.identity,
        default_ctx.is_sandboxed()
    );
    println!("not yet operational: broker core arrives in Slice 2+. See docs/DESIGN.md.");
}
