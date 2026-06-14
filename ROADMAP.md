# Roadmap

This roadmap is published so that anyone evaluating the project can see where it
is going before they invest in it. Items beyond v1 are committed in intent and
the codebase is being structured to receive them (the relevant seams exist in
v1), but timing is not guaranteed.

## v1 (current)

Goal: a trustworthy local control plane for first-party MCP servers, with
presence-gated write elevation and fail-closed behaviour throughout.

- Broker daemon supervising first-party stdio MCP servers (broker is the parent
  process, so it owns lifecycle).
- Read-only IMAP mail MCP server (search, list, fetch) as the first concrete
  server. Runs standalone or under the broker.
- Operator-authoritative read/write tool classification, default-deny.
- Exposure resolution with MCP tools/list_changed, so the model is only offered
  what is currently permitted.
- Presence-gated, time-boxed write elevation via signed single-use assertions.
- Per-action confirmation for destructive tools, even mid-elevation.
- CLI control client: observe and lifecycle, locally and over SSH.
- Single aggregated MCP endpoint, bearer-token authenticated, listener bound to
  loopback or the operator's private network interface.
- macOS only. Built on a platform-abstraction layer so other OSes are additive.

## v2 (designed for in v1, implemented next)

### Third-party servers with sandboxing
The headline v2 capability. Run MCP servers you did not write, safely. Requires
per-child process isolation (so a malicious server cannot read the broker's
secrets or other servers' state) and per-child scoped credentials (each server
gets only what it needs). The v1 child-spawning path already accepts an
injectable execution context for exactly this.

### Multi-user and out-of-band approval
Separate the requester of an elevation from its approver, with approval on a
distinct presence-capable device. This is the natural multi-user authorisation
model and the reason the v1 client-identity model is kept uniform (every client
is a registered, signed identity with no special-casing).

### OAuth 2.1 on the MCP endpoint
Replace the v1 bearer token with spec-compliant OAuth 2.1 plus PKCE for the
Claude-to-broker connection, giving scoped, short-lived, revocable tokens. The
v1 token validation is a pluggable seam so this slots in without reworking the
endpoint. This becomes important precisely when the tool is used by more than one
person or exposed beyond a private network.

### Linux and Windows support
Port the broker and CLI. The security model is platform-neutral; the primitives
are not, so each platform supplies its own presence, key storage, peer identity,
process supervision, and (with sandboxing) isolation. The signed-nonce presence
assertion is the portable primitive and stays primary; platform-specific layers
(such as macOS peer code-signature verification) are bonuses, never the sole
gate. Note the known weak spot: Linux lacks both a universal code-signing
identity and a universal biometric API, so the likely Linux presence path is a
FIDO2 hardware token rather than biometrics.

A native UI beyond macOS (SwiftUI) is intentionally uncommitted. The control API
is the contract; a CLI, a web UI, or a per-platform native UI can all sit on top.

### Out-of-band vulnerability reporting
Add a direct, encrypted reporting channel alongside GitHub's private reporting:
a published contact address and a PGP public key, so reporters who avoid GitHub
or need to send a working exploit can do so without trusting email in the clear.
Deferred until the project has external users; GitHub private reporting is
sufficient at v1 scale.

## Not planned

- Cloud-hosted or multi-tenant SaaS form. This is a tool you run on your own
  host, by design. That is the security model, not a limitation to be removed.
