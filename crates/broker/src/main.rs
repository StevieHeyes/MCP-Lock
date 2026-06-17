//! `mcp-lockd` — the MCP-Lock broker daemon.
//!
//! Slice 2 adds a read-only `--check-manifest <path>` mode: it loads the
//! operator manifest, prints its integrity hash, and prints the cold-start
//! (read-only, zero-elevation) exposure the broker would offer. It spawns
//! nothing and opens no listeners — the aggregator and MCP endpoint arrive in
//! Slice 3, the control channel and elevation in Slice 5.
//!
//! With no arguments it still reports its fail-closed posture and exits.

use std::path::PathBuf;
use std::process::ExitCode;

use mcp_lock_core::broker::BrokerState;
use mcp_lock_core::exec::ExecutionContext;
use mcp_lock_core::manifest;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("mcp-lockd {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--check-manifest") => match args.get(1) {
            Some(path) => check_manifest(PathBuf::from(path)),
            None => {
                eprintln!("mcp-lockd: --check-manifest requires a path");
                ExitCode::from(2)
            }
        },
        None => {
            print_posture();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("mcp-lockd: unknown argument '{other}'");
            eprintln!("run `mcp-lockd --help` for usage");
            ExitCode::from(2)
        }
    }
}

/// Load a manifest read-only and print its integrity hash and the cold-start
/// exposure. Demonstrates the Slice 2 broker core without any transport.
fn check_manifest(path: PathBuf) -> ExitCode {
    let loaded = match manifest::load_from_path(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("mcp-lockd: {e}");
            return ExitCode::from(1);
        }
    };

    // Logging the integrity hash is part of the design: an unexpected change
    // between runs becomes visible here.
    println!("manifest: {}", path.display());
    println!("integrity (sha256): {}", loaded.integrity_sha256);

    let state = BrokerState::from_manifest(&loaded);
    println!(
        "cold start: {} server(s), {} elevation(s)",
        state.servers().len(),
        state.elevation_count()
    );
    // Cold start exposure is evaluated at t=0; everything is read-only.
    for server in state.servers() {
        let exposed = server.exposed(0);
        println!(
            "  [{}] read-only exposure: {}",
            server.id(),
            exposed.join(", ")
        );
    }
    ExitCode::SUCCESS
}

fn print_posture() {
    let default_ctx = ExecutionContext::first_party(Vec::new());
    println!("mcp-lockd {VERSION} (no listeners; broker core only)");
    println!("state: fail-closed — no servers supervised, no tools exposed, zero elevations");
    println!(
        "child execution context: identity={:?}, sandboxed={}",
        default_ctx.identity,
        default_ctx.is_sandboxed()
    );
    println!("try: mcp-lockd --check-manifest <path>   (see docs/DESIGN.md)");
}

fn print_help() {
    println!("mcp-lockd {VERSION} — MCP-Lock broker daemon");
    println!();
    println!("USAGE:");
    println!("    mcp-lockd [--check-manifest <path>]");
    println!();
    println!("FLAGS:");
    println!("    --check-manifest <path>   Load a manifest read-only; print its");
    println!("                              integrity hash and cold-start exposure");
    println!("    -h, --help                Print this help");
    println!("    -V, --version             Print version");
    println!();
    println!("The aggregator/endpoint (Slice 3) and control channel (Slice 5) are not");
    println!("yet implemented; this binary opens no listeners.");
}
