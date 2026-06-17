# CLAUDE.md — orientation for Claude Code sessions

MCP-Lock is a **local control plane for MCP servers on one host**: it supervises child MCP
servers and presents a single, **fail-closed, default-read-only** view of their tools to an
upstream client (Claude). Write/destructive tools are exposed only under an explicit,
time-boxed, presence-gated elevation. Authoritative design lives in
[`docs/DESIGN.md`](docs/DESIGN.md) — read it before any non-trivial change.

## Current state (as of 2026-06-17)
- **v1 is built and merged to `main`.** It shipped as a sequence of stacked "slice" PRs
  (slice-0 scaffolding → slice-5b elevation wiring), all merged in order. `main` is green.
- Platform target is **macOS**. Platform-native security primitives are seams with stubs
  (see below); v1 uses documented dev stand-ins for them.
- **Open work is tracked in GitHub issues, milestoned `v1` / `v2`.** Get the live list with
  `gh issue list --milestone v2` (and `--milestone v1`). Don't infer the roadmap from code —
  read the issues. Issues + milestones are the primary work-list for a session.
- A human-facing roadmap board mirrors the same issues:
  [MCP-Lock project](https://github.com/users/StevieHeyes/projects/1) (reading it needs the
  `project` gh scope; the issues above are the scope-free source of truth).

## Workspace map (Cargo workspace, edition 2021, toolchain pinned 1.96.0)
| Path | Package | Produces | Role |
|---|---|---|---|
| `crates/core` | `mcp-lock-core` | lib | **Security core.** Pure, synchronous, dependency-light: manifest, tool classification/policy, broker state, auth seam, elevation (ed25519 challenge/response), audit log, platform trait seams. No transport, no async. |
| `crates/transport` | `mcp-lock-transport` | lib | Edge I/O: the upward HTTP/SSE MCP endpoint (bearer-auth'd) and the local Unix-socket control channel. |
| `crates/broker` | `mcp-lockd` | daemon | The broker: spawns/supervises children, aggregates + gates their tools, serves the MCP endpoint and control channel. |
| `crates/cli` | `mcp-lock` | CLI | Operator CLI over the control channel (observe, lifecycle, elevate/confirm/revoke). |
| `crates/mail` | `mcp-lock-mail` | server | A read-only IMAP mail MCP server — the first supervised child and an edge component. |

Request flow: upstream client → `transport` HTTP endpoint → `broker::handler` → `broker::aggregator`
(applies `core::policy` exposure gate) → child via `broker::mcp_client` (stdio JSON-RPC).

## Hard conventions — do not violate
- **Fail closed.** Anything unexpected (child crash/hang, missed timer, lock poisoning) must
  reduce exposure to read-only and drop elevations, never open up. Default-deny: a tool not
  classified `read` in the manifest is gated.
- **`unsafe_code` is denied workspace-wide** (`[workspace.lints]`). No `unsafe`, no libc. Use
  safe std (threads + channels) for things like socket timeouts.
- **Secrets never logged.** Types holding tokens/keys/passwords have hand-written `Debug` that
  redacts; the configured bearer token is scrubbed on drop.
- **Elevation never persists.** Broker state is rebuilt from the manifest on start, so an
  elevation cannot survive a restart — this is structural, keep it that way.
- **The manifest is operator-authoritative.** A child's self-declared hints are used only to
  *propose* a classification at registration, never trusted at runtime.
- **Slice discipline.** Work lands as small, reviewable, stacked PRs that each pass CI on their
  own. Keep changes scoped to one concern.

## Verify like CI does (run before claiming anything passes)
The CI gate (`.github/workflows/ci.yml`) — match it exactly, and check the **exit code** (do
not pipe `cargo fmt --check` into `tail`; a pipe masks its failure):
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```
CI also runs `cargo-deny` (advisories/licenses/sources), `gitleaks` (secret scan, checksum-verified),
and a Linux `cargo check` (portability of the platform-agnostic trait layer). Tests, fmt, and
clippy run on macOS because the platform providers compile under `cfg(target_os = "macos")`.

Expected non-issue: a `future-incompat` warning from the transitive `imap-proto 0.10.2` dep
(see issue #16). It builds clean on 1.96.0 and does not fail CI — don't "fix" it by pulling an
alpha `imap` 3.x.

## Running it
- Inspect a manifest (read-only): `cargo run -p mcp-lockd -- --check-manifest <path>`
  (example at `examples/manifest.example.json`).
- Serve: `cargo run -p mcp-lockd -- serve`. Key env vars (broker): `MCPLOCK_BEARER_TOKEN`
  (required — ship-closed), `MCPLOCK_LISTEN`, `MCPLOCK_CLIENTS` (registered client keys JSON),
  `MCPLOCK_AUDIT_LOG`, `MCPLOCK_CONTROL_SOCK`. CLI client: `MCPLOCK_CLIENT_ID`,
  `MCPLOCK_SIGNING_KEY` (dev signing seed — to be replaced by Keychain/Secure Enclave, issue #13).
  Mail server: `MAIL_IMAP_HOST` / `MAIL_IMAP_PORT` / IMAP user + password from env.

## Platform seams stubbed in v1 (macOS), tracked for v2
`crates/core/src/platform/` defines traits that return `Unsupported` on macOS in v1:
`SecureKeyStore` (→ Keychain, issue #11), `PresenceProvider` (→ Secure Enclave / Touch ID
signing, issue #13), `PeerIdentityVerifier` (→ code-signature check over the control socket,
issue #14). Remote mTLS control channel is #12; audit hash-chaining is #15; SwiftUI UI is #10.
