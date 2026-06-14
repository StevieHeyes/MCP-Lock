# MCP-Lock

⚠️ **Work in Progress** — This project is in active development. The API, feature set, and configuration format are not yet stable. Use at your own risk.

A local control plane for managing MCP servers on one host. See what is running,
start/stop/pause servers, and grant write access on demand: time-boxed, gated by
human presence, default read-only, fail-closed.

## Status and disclaimer

This is a personal project, built and maintained on a best-effort basis in spare
time. It is provided "as is", without warranty of any kind. See [LICENSE](LICENSE)
for the controlling warranty disclaimer and limitation of liability.

It is a security tool that can hold credentials. You run it at your own risk. You
are responsible for reviewing the code, configuring it correctly, and deciding
whether it is fit for your purposes before trusting it with anything sensitive.
Read [SECURITY.md](SECURITY.md) before deploying it.

Contributions are welcome. There is no service-level commitment, no guaranteed
response time beyond the best-effort acknowledgement in SECURITY.md, and no
obligation to fix any issue. The maintainers accept no liability for any loss or
damage arising from use of this software.

## What it is

Most MCP setups wire a client directly to each server. This project puts a broker
in between: a single long-running daemon that supervises your MCP servers and
presents one endpoint to the AI client. Because the broker is the parent process
of every server, it can start, stop, and pause them, and because every tool call
flows through it, it can enforce a read/write boundary that the servers
themselves do not control.

The motivating use case is mail: run a mail server read-only by default, and
elevate to send/delete only on demand, briefly, with a presence check.

## Security model in brief

- Default-deny: tools are read-only unless explicitly elevated; anything
  unclassified is treated as write and gated.
- Fail-closed: cold start, faults, and elevation expiry all revert to read-only.
  Elevation never survives a restart.
- The UI is not the security boundary; the control channel and the broker's
  process identity are.
- Presence, not tokens: write elevation is bound to a fresh, single-use signed
  presence assertion, so a credential at rest cannot be replayed to elevate.
- Ship closed: no baked-in token or default privileged mode; a fresh install
  refuses privileged actions until you register a client.

The full model, including what it does NOT protect against, is in
[SECURITY.md](SECURITY.md). Read that before trusting it with anything.

## Project status

In active development. v1 is being built as a sequence of small, independently
working vertical slices. The current scope and the path beyond it are in
[ROADMAP.md](ROADMAP.md); the full design is in [docs/DESIGN.md](docs/DESIGN.md).

v1 targets macOS and supports first-party (operator-authored) servers only. Do
not add third-party servers to v1: see the scope note in SECURITY.md.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): full architecture and security design.
- [SECURITY.md](SECURITY.md): security model, threat model, honest ceiling,
  reporting.
- [ROADMAP.md](ROADMAP.md): v1 scope and committed direction beyond it.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to propose and submit changes.

## Installation

Building from source is the only supported path. There are no prebuilt binaries.

Requirements:

- macOS (v1 is macOS only).
- A Rust toolchain. The exact version is pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml); if you use `rustup`, it is
  installed automatically on first build, with the `rustfmt` and `clippy`
  components.

Build the whole workspace:

    cargo build --release

This produces these binaries under `target/release/`:

- `mcp-lock-mail` — the read-only IMAP mail MCP server (Slice 1; runnable).
- `mcp-lockd` — the broker daemon (scaffolding).
- `mcp-lock` — the control CLI (scaffolding).

As of Slice 1, `mcp-lock-mail` is a working stdio MCP server (see Usage).
`mcp-lockd` and `mcp-lock` are still scaffolding: `mcp-lockd` starts, reports its
fail-closed posture, and exits without supervising any servers, and `mcp-lock`
answers `--help`/`--version` only. They become functional in later slices.

## Usage

<!-- TODO(agent): extend when Slice 5 lands — the presence-gated elevation flow.
Keep examples accurate to shipped behaviour only. -->

### Read-only mail server, standalone (Slice 1)

`mcp-lock-mail` is a stdio [MCP](https://modelcontextprotocol.io) server exposing
three read-only tools — `search`, `list_messages`, and `fetch_message` — over an
IMAP account. It runs directly against an MCP client without the broker.

**Try it with no account (in-memory demo).** This serves a small built-in
fixture, so it needs no network and no credentials:

    mcp-lock-mail --fake

**Against a real account.** Credentials come from the environment only; the
server never prompts for or stores a password. Use an app-specific password where
your provider supports one.

    export MAIL_IMAP_HOST=imap.example.com
    export MAIL_IMAP_USERNAME=you@example.com
    export MAIL_IMAP_PASSWORD=...        # app password; never commit this
    # optional: MAIL_IMAP_PORT (default 993), MAIL_DEFAULT_MAILBOX (default INBOX)
    mcp-lock-mail

**Wiring into an MCP client.** Point the client at the binary as a stdio server.
For example, in a Claude client's MCP config:

    {
      "mcpServers": {
        "mail": {
          "command": "/absolute/path/to/mcp-lock-mail",
          "env": {
            "MAIL_IMAP_HOST": "imap.example.com",
            "MAIL_IMAP_USERNAME": "you@example.com",
            "MAIL_IMAP_PASSWORD": "..."
          }
        }
      }
    }

The server opens mailboxes read-only (IMAP `EXAMINE`) and fetches with
`BODY.PEEK`, so it never marks messages read or alters mailbox state. It exposes
no tool that can send, move, flag, or delete mail — by design (see
[SECURITY.md](SECURITY.md) on the data-plane / prompt-injection surface).

### Running the broker (Slice 3)

The broker (`mcp-lockd`) supervises servers declared in a manifest and presents a
single, fail-closed, bearer-authenticated MCP endpoint. See
[`examples/manifest.example.json`](examples/manifest.example.json) for the format;
each server's tools are classified `read`, `write`, or `confirm`
(operator-authoritative — a child cannot widen its own surface).

Inspect a manifest without starting anything (prints the integrity hash and the
read-only cold-start exposure):

    mcp-lockd --check-manifest examples/manifest.example.json

Serve the aggregated endpoint. It **ships closed**: it refuses to start without a
bearer token.

    export MCPLOCK_BEARER_TOKEN=...          # required; no default token
    # optional: MCPLOCK_LISTEN (default 127.0.0.1:8765)
    mcp-lockd serve --manifest /path/to/manifest.json

Point an MCP client at `http://127.0.0.1:8765/` with an
`Authorization: Bearer <token>` header. In the default (un-elevated) state only
read tools are offered; tool names are namespaced `server.tool` (e.g.
`mail.search`).

### Controlling the broker with the CLI (Slice 4)

`mcp-lock` talks to a running broker over a local Unix socket
(`$MCPLOCK_CONTROL_SOCK`, or a default under the temp dir) to observe and drive
lifecycle. Lifecycle requires no presence — the worst a terminal attacker can do
is deny service, never escalate.

    mcp-lock status            # servers, state, exposed tool count
    mcp-lock list              # currently exposed (namespaced) tools
    mcp-lock logs [N]          # recent broker log lines
    mcp-lock pause <id>        # stop exposing/routing a server (instant resume)
    mcp-lock resume <id>
    mcp-lock stop <id>         # terminate a server
    mcp-lock start <id>        # (re)start a server, read-only

Presence-gated write elevation arrives in Slice 5.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Note that security-sensitive changes
receive extra scrutiny and that security issues must be reported privately, never
in a public issue or pull request.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Contributions are accepted under the same license (see
CONTRIBUTING.md).
