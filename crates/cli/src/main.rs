//! `mcp-lock` — the MCP-Lock control CLI.
//!
//! Talks to a running `mcp-lockd` over the local control channel (a Unix socket)
//! to observe, drive lifecycle, and elevate:
//!
//! * observe: `status`, `list`, `logs [N]`
//! * lifecycle: `start|stop|pause|resume <server-id>` (no presence required)
//! * elevation: `elevate <server-id> [--ttl <secs> | --until-revoked]`,
//!   `confirm <server-id> <tool>`, `revoke <server-id>`
//!
//! Elevation and confirm sign a broker-issued challenge. In v1 the CLI signs with
//! a dev key from `$MCPLOCK_SIGNING_KEY` (hex 32-byte seed); presence-gated
//! Keychain/Secure-Enclave signing is a documented follow-up. The client id is
//! `$MCPLOCK_CLIENT_ID` (default `operator`) and must be registered with the
//! broker. The socket path is `$MCPLOCK_CONTROL_SOCK` or a default.

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
    match args[0].as_str() {
        "elevate" => unix_impl::elevate(args),
        "confirm" => unix_impl::confirm(args),
        _ => unix_impl::simple(args),
    }
}

#[cfg(unix)]
mod unix_impl {
    use std::process::ExitCode;

    use ed25519_dalek::{Signer, SigningKey};
    use mcp_lock_core::elevation::{challenge_message, Nonce, Purpose, RequestedMode};
    use mcp_lock_transport::control::{
        socket_path, ControlClient, ControlRequest, ControlResponse,
    };

    const CLIENT_ENV: &str = "MCPLOCK_CLIENT_ID";
    const KEY_ENV: &str = "MCPLOCK_SIGNING_KEY";
    const DEFAULT_CLIENT: &str = "operator";
    const DEFAULT_TTL_SECS: u64 = 300;

    /// Single round-trip commands: observe + lifecycle + revoke.
    pub(crate) fn simple(args: &[String]) -> ExitCode {
        let request = match parse_simple(args) {
            Ok(req) => req,
            Err(message) => return usage_error(&message),
        };
        match send(&request) {
            Ok(resp) => print_response(resp),
            Err(code) => code,
        }
    }

    /// Two-step elevation: request a nonce, sign it, submit.
    pub(crate) fn elevate(args: &[String]) -> ExitCode {
        let Some(server) = args.get(1).cloned() else {
            return usage_error("`elevate` requires a server id");
        };
        let mode = match parse_mode(&args[2..]) {
            Ok(m) => m,
            Err(message) => return usage_error(&message),
        };
        let (client_id, signing) = match load_identity() {
            Ok(v) => v,
            Err(message) => return usage_error(&message),
        };

        let (mode_str, ttl) = match mode {
            RequestedMode::Duration { ttl_secs } => ("duration", Some(ttl_secs)),
            RequestedMode::UntilRevoked => ("until_revoked", None),
        };
        let purpose = Purpose::Elevate {
            server_id: server.clone(),
            mode,
        };
        submit_signed(
            &signing,
            &client_id,
            ControlRequest::RequestElevation {
                client_id: client_id.clone(),
                server_id: server,
                mode: mode_str.to_string(),
                ttl_secs: ttl,
            },
            purpose,
        )
    }

    /// Two-step per-action confirm: request a nonce for one tool, sign, submit.
    pub(crate) fn confirm(args: &[String]) -> ExitCode {
        let (Some(server), Some(tool)) = (args.get(1).cloned(), args.get(2).cloned()) else {
            return usage_error("`confirm` requires a server id and a tool name");
        };
        let (client_id, signing) = match load_identity() {
            Ok(v) => v,
            Err(message) => return usage_error(&message),
        };
        let purpose = Purpose::Confirm {
            server_id: server.clone(),
            tool: tool.clone(),
        };
        submit_signed(
            &signing,
            &client_id,
            ControlRequest::RequestConfirm {
                client_id: client_id.clone(),
                server_id: server,
                tool,
            },
            purpose,
        )
    }

    /// Run a request that yields a nonce, sign the challenge for `purpose`, and
    /// submit it. `is_confirm` selects which submit message to send.
    fn submit_signed(
        signing: &SigningKey,
        client_id: &str,
        request_nonce: ControlRequest,
        purpose: Purpose,
    ) -> ExitCode {
        let is_confirm = matches!(purpose, Purpose::Confirm { .. });
        let nonce_hex = match send(&request_nonce) {
            Ok(ControlResponse::Nonce { nonce }) => nonce,
            Ok(ControlResponse::Error { message }) => return fail(&message),
            Ok(_) => return fail("unexpected response to nonce request"),
            Err(code) => return code,
        };
        let Some(nonce) = Nonce::from_hex(&nonce_hex) else {
            return fail("broker returned a malformed nonce");
        };
        let message = challenge_message(&nonce, client_id, &purpose);
        let signature = signing.sign(&message);
        let sig_hex = to_hex(&signature.to_bytes());

        let submit = if is_confirm {
            ControlRequest::SubmitConfirm {
                client_id: client_id.to_string(),
                nonce: nonce_hex,
                signature: sig_hex,
            }
        } else {
            ControlRequest::SubmitElevation {
                client_id: client_id.to_string(),
                nonce: nonce_hex,
                signature: sig_hex,
            }
        };
        match send(&submit) {
            Ok(resp) => print_response(resp),
            Err(code) => code,
        }
    }

    fn parse_simple(args: &[String]) -> Result<ControlRequest, String> {
        let command = args[0].as_str();
        let id = |args: &[String]| {
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
            "start" => Ok(ControlRequest::Start { id: id(args)? }),
            "stop" => Ok(ControlRequest::Stop { id: id(args)? }),
            "pause" => Ok(ControlRequest::Pause { id: id(args)? }),
            "resume" => Ok(ControlRequest::Resume { id: id(args)? }),
            "revoke" => Ok(ControlRequest::Revoke { id: id(args)? }),
            other => Err(format!("unknown command '{other}'")),
        }
    }

    fn parse_mode(flags: &[String]) -> Result<RequestedMode, String> {
        let mut ttl = DEFAULT_TTL_SECS;
        let mut until_revoked = false;
        let mut i = 0;
        while i < flags.len() {
            match flags[i].as_str() {
                "--until-revoked" => until_revoked = true,
                "--ttl" => {
                    let v = flags
                        .get(i + 1)
                        .ok_or_else(|| "--ttl requires a number of seconds".to_string())?;
                    ttl = v
                        .parse::<u64>()
                        .map_err(|_| "--ttl must be a number".to_string())?;
                    i += 1;
                }
                other => return Err(format!("unknown flag '{other}'")),
            }
            i += 1;
        }
        if until_revoked {
            Ok(RequestedMode::UntilRevoked)
        } else {
            Ok(RequestedMode::Duration { ttl_secs: ttl })
        }
    }

    fn load_identity() -> Result<(String, SigningKey), String> {
        let client_id = std::env::var(CLIENT_ENV).unwrap_or_else(|_| DEFAULT_CLIENT.to_string());
        let hex = std::env::var(KEY_ENV).map_err(|_| {
            format!(
                "{KEY_ENV} is not set. Elevation needs a signing key; set {KEY_ENV} to a hex \
                 32-byte seed (dev path). Presence-gated Keychain signing is a follow-up."
            )
        })?;
        let seed = decode_32(&hex)
            .ok_or_else(|| format!("{KEY_ENV} must be a 64-character hex (32-byte) seed"))?;
        Ok((client_id, SigningKey::from_bytes(&seed)))
    }

    fn send(request: &ControlRequest) -> Result<ControlResponse, ExitCode> {
        let path = socket_path();
        ControlClient::request(&path, request).map_err(|e| {
            eprintln!("mcp-lock: cannot reach broker at {} ({e})", path.display());
            eprintln!("is mcp-lockd running? (set MCPLOCK_CONTROL_SOCK to override the path)");
            ExitCode::from(1)
        })
    }

    fn print_response(response: ControlResponse) -> ExitCode {
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
            ControlResponse::Nonce { .. } => fail("unexpected nonce response"),
            ControlResponse::Done { message } => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            ControlResponse::Error { message } => fail(&message),
        }
    }

    fn fail(message: &str) -> ExitCode {
        eprintln!("mcp-lock: {message}");
        ExitCode::from(1)
    }

    fn usage_error(message: &str) -> ExitCode {
        eprintln!("mcp-lock: {message}");
        eprintln!("run `mcp-lock --help` for usage");
        ExitCode::from(2)
    }

    fn decode_32(hex: &str) -> Option<[u8; 32]> {
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(out)
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
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
    println!("ELEVATION (presence-gated; signs a broker-issued challenge):");
    println!("    elevate <id> [--ttl <secs> | --until-revoked]   Grant write access");
    println!("    confirm <id> <tool>                             Approve one confirm-tool action");
    println!("    revoke  <id>                                    Revoke write access");
    println!();
    println!("FLAGS:");
    println!("    -h, --help        Print this help");
    println!("    -V, --version     Print version");
    println!();
    println!("Connects via $MCPLOCK_CONTROL_SOCK. Elevation signs with");
    println!("$MCPLOCK_SIGNING_KEY (hex 32-byte seed; dev path) as $MCPLOCK_CLIENT_ID");
    println!("(default 'operator'). Keychain/Secure-Enclave signing is a follow-up.");
}
