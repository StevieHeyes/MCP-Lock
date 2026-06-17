//! `mcp-lock` — the MCP-Lock control CLI.
//!
//! In Slice 0 this is scaffolding: it answers `--version` and `--help` and
//! otherwise reports that no commands are wired yet. The real surface lands in
//! Slice 4 (observe: status/logs/list; lifecycle: start/stop/pause/resume) over
//! the control channel, with elevation following in Slice 5.
//!
//! Per `docs/DESIGN.md`, lifecycle commands will require no presence (worst case
//! for a terminal attacker is denial of service, never escalation); elevation is
//! fully presence-gated.

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("mcp-lock {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("mcp-lock: unknown command '{other}'");
            eprintln!("run `mcp-lock --help` for usage");
            // Exit 2 for usage errors, by convention.
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!("mcp-lock {VERSION} — MCP-Lock control client");
    println!();
    println!("USAGE:");
    println!("    mcp-lock [COMMAND]");
    println!();
    println!("FLAGS:");
    println!("    -h, --help       Print this help");
    println!("    -V, --version    Print version");
    println!();
    println!("COMMANDS (not yet implemented — arrive in Slice 4):");
    println!("    status           Show supervised servers and exposure state");
    println!("    logs             Show broker / audit logs");
    println!("    list             List currently exposed tools");
    println!("    start|stop|pause|resume   Lifecycle control (no presence required)");
    println!();
    println!("Elevation (presence-gated) arrives in Slice 5. See docs/DESIGN.md.");
}
