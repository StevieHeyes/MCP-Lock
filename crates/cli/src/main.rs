//! `mcp-lock` — the MCP-Lock control CLI.
//!
//! Talks to a running `mcp-lockd` over the local control channel (a Unix socket)
//! to observe and drive lifecycle:
//!
//! * observe: `status`, `list`, `logs [N]`
//! * lifecycle: `start|stop|pause|resume <server-id>` (no presence required)
//!
//! Presence-gated elevation arrives in Slice 5. The socket path is
//! `$MCPLOCK_CONTROL_SOCK` or a default under the temp dir.

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
        Some(_) => run(&args),
    }
}

#[cfg(unix)]
fn run(args: &[String]) -> ExitCode {
    use mcp_lock_transport::control::{socket_path, ControlClient, ControlResponse};

    // Parse the subcommand into a request.
    let request = match parse_request(args) {
        Ok(req) => req,
        Err(message) => {
            eprintln!("mcp-lock: {message}");
            eprintln!("run `mcp-lock --help` for usage");
            return ExitCode::from(2);
        }
    };

    let path = socket_path();
    let response = match ControlClient::request(&path, &request) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("mcp-lock: cannot reach broker at {} ({e})", path.display());
            eprintln!("is mcp-lockd running? (set MCPLOCK_CONTROL_SOCK to override the path)");
            return ExitCode::from(1);
        }
    };

    match response {
        ControlResponse::Status { servers } => {
            if servers.is_empty() {
                println!("(no servers)");
            }
            for s in servers {
                let elevated = if s.elevated { " (elevated)" } else { "" };
                println!(
                    "{:<16} {:<8} {} tool(s) exposed{}",
                    s.id, s.state, s.exposed_tools, elevated
                );
            }
            ExitCode::SUCCESS
        }
        ControlResponse::List { tools } => {
            if tools.is_empty() {
                println!("(no tools exposed)");
            }
            for t in tools {
                println!("{t}");
            }
            ExitCode::SUCCESS
        }
        ControlResponse::Logs { entries } => {
            for e in entries {
                println!("{e}");
            }
            ExitCode::SUCCESS
        }
        ControlResponse::Done { message } => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        ControlResponse::Error { message } => {
            eprintln!("mcp-lock: {message}");
            ExitCode::from(1)
        }
    }
}

#[cfg(unix)]
fn parse_request(args: &[String]) -> Result<mcp_lock_transport::control::ControlRequest, String> {
    use mcp_lock_transport::control::ControlRequest;

    let command = args[0].as_str();
    let lifecycle = |args: &[String]| -> Result<String, String> {
        args.get(1)
            .cloned()
            .ok_or_else(|| format!("`{command}` requires a server id"))
    };

    match command {
        "status" => Ok(ControlRequest::Status),
        "list" => Ok(ControlRequest::List),
        "logs" => {
            let limit = match args.get(1) {
                None => None,
                Some(n) => Some(
                    n.parse::<usize>()
                        .map_err(|_| "logs <N>: N must be a number".to_string())?,
                ),
            };
            Ok(ControlRequest::Logs { limit })
        }
        "start" => Ok(ControlRequest::Start {
            id: lifecycle(args)?,
        }),
        "stop" => Ok(ControlRequest::Stop {
            id: lifecycle(args)?,
        }),
        "pause" => Ok(ControlRequest::Pause {
            id: lifecycle(args)?,
        }),
        "resume" => Ok(ControlRequest::Resume {
            id: lifecycle(args)?,
        }),
        other => Err(format!("unknown command '{other}'")),
    }
}

#[cfg(not(unix))]
fn run(_args: &[String]) -> ExitCode {
    eprintln!("mcp-lock: the control channel is only available on Unix platforms");
    ExitCode::from(1)
}

fn print_help() {
    println!("mcp-lock {VERSION} — MCP-Lock control client");
    println!();
    println!("USAGE:");
    println!("    mcp-lock <COMMAND>");
    println!();
    println!("OBSERVE:");
    println!("    status            Show supervised servers and exposure");
    println!("    list              List currently exposed tools");
    println!("    logs [N]          Show the last N broker log lines (default 50)");
    println!();
    println!("LIFECYCLE (no presence required):");
    println!("    start <id>        Start (or restart) a server, read-only");
    println!("    stop <id>         Stop a server");
    println!("    pause <id>        Pause a server (instant resume)");
    println!("    resume <id>       Resume a paused server");
    println!();
    println!("FLAGS:");
    println!("    -h, --help        Print this help");
    println!("    -V, --version     Print version");
    println!();
    println!("Connects to mcp-lockd via $MCPLOCK_CONTROL_SOCK (or a default).");
    println!("Presence-gated elevation arrives in Slice 5.");
}
