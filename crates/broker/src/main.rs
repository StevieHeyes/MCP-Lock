//! `mcp-lockd` — the MCP-Lock broker daemon.
//!
//! Slice 2 adds a read-only `--check-manifest <path>` mode: it loads the
//! operator manifest, prints its integrity hash, and prints the cold-start
//! (read-only, zero-elevation) exposure the broker would offer. It spawns
//! nothing and opens no listeners — the aggregator and MCP endpoint arrive in
//! Slice 3, the control channel and elevation in Slice 5.
//!
//! With no arguments it still reports its fail-closed posture and exits.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use mcp_lock_core::auth::StaticBearerValidator;
use mcp_lock_core::broker::BrokerState;
use mcp_lock_core::exec::ExecutionContext;
use mcp_lock_core::manifest::{self, ServerManifest};
use mcp_lock_transport::control::{self, ControlHandler, ControlServer};
use mcp_lock_transport::endpoint::{HttpEndpoint, Notifier};

use mcp_lockd::aggregator::Aggregator;
use mcp_lockd::control_handler::BrokerControlHandler;
use mcp_lockd::handler::BrokerMcpHandler;
use mcp_lockd::mcp_client::{ChildError, McpChild, StdioMcpClient};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Env var the bearer token for the MCP endpoint is read from. Ship-closed: if
/// unset/empty, `serve` refuses to start.
const TOKEN_ENV: &str = "MCPLOCK_BEARER_TOKEN";
/// Env var for the listen address. Defaults to loopback.
const LISTEN_ENV: &str = "MCPLOCK_LISTEN";
const DEFAULT_LISTEN: &str = "127.0.0.1:8765";

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
        Some("serve") => match args.get(1).map(String::as_str) {
            Some("--manifest") => match args.get(2) {
                Some(path) => serve(PathBuf::from(path)),
                None => {
                    eprintln!("mcp-lockd: serve --manifest requires a path");
                    ExitCode::from(2)
                }
            },
            _ => {
                eprintln!("mcp-lockd: usage: serve --manifest <path>");
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

/// Spawn the manifest's servers and serve the aggregated, fail-closed MCP
/// endpoint over HTTP on loopback. Blocks until killed.
fn serve(path: PathBuf) -> ExitCode {
    let loaded = match manifest::load_from_path(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("mcp-lockd: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "mcp-lockd {VERSION}: manifest {} ({})",
        path.display(),
        loaded.integrity_sha256
    );

    // Ship closed: no token, no endpoint.
    let token = std::env::var(TOKEN_ENV).unwrap_or_default();
    let Some(validator) = StaticBearerValidator::new(&token, "mcp-client") else {
        eprintln!("mcp-lockd: refusing to start — set {TOKEN_ENV} to a non-empty bearer token");
        return ExitCode::from(1);
    };

    // Spawn and supervise the child servers (broker is the parent).
    let aggregator = match Aggregator::build(&loaded, spawn_child) {
        Ok(agg) => agg,
        Err(e) => {
            eprintln!("mcp-lockd: failed to start servers: {e}");
            return ExitCode::from(1);
        }
    };

    // Share the aggregator and the notifier between the MCP endpoint and the
    // control channel, so a lifecycle change on the control channel fires
    // tools/list_changed to MCP clients.
    let aggregator = Arc::new(Mutex::new(aggregator));
    let notifier = Notifier::new();

    let mcp_handler = Arc::new(BrokerMcpHandler::new(aggregator.clone()));
    let listen = std::env::var(LISTEN_ENV).unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let endpoint =
        match HttpEndpoint::bind(&listen, Arc::new(validator), mcp_handler, notifier.clone()) {
            Ok(ep) => ep,
            Err(e) => {
                eprintln!("mcp-lockd: could not bind {listen}: {e}");
                return ExitCode::from(1);
            }
        };

    // Start the local control channel (observe + lifecycle). A failure here is
    // non-fatal: the MCP endpoint still serves read-only.
    start_control_channel(aggregator, notifier);

    eprintln!(
        "mcp-lockd: MCP endpoint listening on http://{} (read-only until elevated)",
        endpoint.local_addr()
    );
    endpoint.run();
    ExitCode::SUCCESS
}

/// Bind the control socket and serve it on a background thread.
fn start_control_channel(aggregator: Arc<Mutex<Aggregator>>, notifier: Notifier) {
    let path = control::socket_path();
    let handler: Arc<dyn ControlHandler> =
        Arc::new(BrokerControlHandler::new(aggregator, notifier));
    match ControlServer::bind(&path) {
        Ok(server) => {
            eprintln!("mcp-lockd: control socket at {}", path.display());
            std::thread::spawn(move || server.run(handler));
        }
        Err(e) => {
            eprintln!("mcp-lockd: warning: control channel unavailable ({e})");
        }
    }
}

/// Spawn one child server under the v1 execution context (first-party, no
/// sandbox), passing the manifest's non-secret env.
fn spawn_child(server: &ServerManifest) -> Result<Box<dyn McpChild>, ChildError> {
    let ctx = ExecutionContext::first_party(Vec::new());
    let env: BTreeMap<String, String> = server.env.clone();
    StdioMcpClient::spawn(&server.command, &server.args, &ctx, &env)
        .map(|c| Box::new(c) as Box<dyn McpChild>)
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
    println!("    mcp-lockd serve --manifest <path>");
    println!("    mcp-lockd --check-manifest <path>");
    println!();
    println!("COMMANDS:");
    println!("    serve --manifest <path>   Spawn the manifest's servers and serve the");
    println!("                              aggregated MCP endpoint over HTTP (loopback).");
    println!("                              Requires {TOKEN_ENV}; binds {LISTEN_ENV}");
    println!("                              (default {DEFAULT_LISTEN}).");
    println!();
    println!("FLAGS:");
    println!("    --check-manifest <path>   Load a manifest read-only; print its");
    println!("                              integrity hash and cold-start exposure");
    println!("    -h, --help                Print this help");
    println!("    -V, --version             Print version");
    println!();
    println!("The control channel and presence-gated elevation arrive in Slice 5.");
}
