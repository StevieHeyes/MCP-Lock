//! `mcp-lock-mail` — read-only IMAP mail MCP server (stdio).
//!
//! Usage:
//! * `mcp-lock-mail` — run against a real IMAP account (config from env).
//! * `mcp-lock-mail --fake` — run against the built-in in-memory demo fixture
//!   (no network, no credentials), useful for trying the server against an MCP
//!   client.
//! * `mcp-lock-mail --help | --version`
//!
//! stdout carries the JSON-RPC protocol stream and nothing else; all diagnostics
//! go to stderr.

use std::io::{self, BufReader};
use std::process::ExitCode;

use mcp_lock_mail::config::ImapConfig;
use mcp_lock_mail::fake::FakeMailStore;
use mcp_lock_mail::imap_backend::ImapBackend;
use mcp_lock_mail::server::Server;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SERVER_NAME: &str = "mcp-lock-mail";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("{SERVER_NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--fake") => run_fake(),
        None => run_real(),
        Some(other) => {
            eprintln!("{SERVER_NAME}: unknown argument '{other}'");
            eprintln!("run `{SERVER_NAME} --help` for usage");
            ExitCode::from(2)
        }
    }
}

/// Run against the in-memory demo fixture.
fn run_fake() -> ExitCode {
    eprintln!("{SERVER_NAME} {VERSION}: starting with in-memory demo fixture (no network)");
    let store = FakeMailStore::demo();
    let server = Server::new(store, SERVER_NAME, VERSION, "INBOX");
    serve(&server)
}

/// Run against a real IMAP account configured from the environment.
fn run_real() -> ExitCode {
    let config = match ImapConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{SERVER_NAME}: configuration error: {e}");
            eprintln!("set the MAIL_IMAP_* environment variables (see README), or use --fake");
            return ExitCode::from(1);
        }
    };
    // Debug is redacted, so this cannot print the password.
    eprintln!(
        "{SERVER_NAME} {VERSION}: starting (host={}, port={}, default_mailbox={})",
        config.host, config.port, config.default_mailbox
    );
    let default_mailbox = config.default_mailbox.clone();
    let backend = ImapBackend::new(config);
    let server = Server::new(backend, SERVER_NAME, VERSION, default_mailbox);
    serve(&server)
}

/// Drive the server over stdio.
fn serve<S: mcp_lock_mail::mailstore::MailStore>(server: &Server<S>) -> ExitCode {
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    let writer = io::stdout().lock();
    match server.run(reader, writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{SERVER_NAME}: I/O error: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_help() {
    println!("{SERVER_NAME} {VERSION} — read-only IMAP mail MCP server (stdio)");
    println!();
    println!("USAGE:");
    println!("    {SERVER_NAME} [--fake]");
    println!();
    println!("FLAGS:");
    println!("    --fake           Serve a built-in in-memory demo fixture (no network)");
    println!("    -h, --help       Print this help");
    println!("    -V, --version    Print version");
    println!();
    println!("TOOLS (all read-only): search, list_messages, fetch_message");
    println!();
    println!("CONFIG (real mode, from environment):");
    println!("    MAIL_IMAP_HOST       IMAP server hostname (required)");
    println!("    MAIL_IMAP_PORT       IMAP server port (default 993)");
    println!("    MAIL_IMAP_USERNAME   IMAP username (required)");
    println!("    MAIL_IMAP_PASSWORD   IMAP password / app password (required)");
    println!("    MAIL_DEFAULT_MAILBOX Default mailbox (default INBOX)");
}
