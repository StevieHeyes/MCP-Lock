# MCP-Lock — v1 Design & Handover

## Purpose
A local control plane for managing multiple MCP servers running on one host.
It lets an operator see what is running, start/stop/pause servers, and grant
write access on demand, time-boxed and gated by human presence, with everything
defaulting to read-only and failing closed.

## Audience
The engineer (or AI agent) building v1, and future contributors after open-sourcing.

## Scope

### In scope for v1
- Broker daemon that supervises first-party (operator-authored) stdio MCP servers.
- A first concrete server: a read-only IMAP mail MCP server (search/list/fetch).
- Read/write tool classification with default-deny and fail-closed behaviour.
- Presence-gated, time-boxed write elevation.
- CLI control client (observe + lifecycle locally and over SSH).
- Single MCP endpoint that aggregates child servers for a Claude client.

### Explicitly NOT in v1 (designed for, deferred)
- Third-party / untrusted servers and per-child sandboxing (v2).
- Multi-user / out-of-band approval (v2).
- OAuth 2.1 on the MCP endpoint (v2).
- Native SwiftUI UI (later slice; CLI is the v1 control surface).
- Linux/Windows implementations (roadmap; v1 is macOS, but the code is
  structured so ports are additive, not rewrites).

## Architecture: three tiers

        +-----------------------+
        |   Control client(s)   |  GUI (later) and CLI. Thin. No enforcement.
        |  (SwiftUI / mcp-lock) |  May be local or remote.
        +-----------+-----------+
                    | Control API
                    | UDS (local) or mTLS over Tailscale (remote)
        +-----------v---------------------------------+
        |          BROKER  (mcp-lockd daemon)         |
        |  Runs as a dedicated service account.       |
        |  Supervised by launchd (KeepAlive).         |
        |                                             |
        |  [MCP endpoint] <----> [Policy + audit]     |
        |   HTTP/SSE upward       exposure resolution |
        |        |                fail-closed         |
        |        | stdio downward (broker is PARENT)  |
        +--------+----------+-------------+-----------+
                 |          |             |
            +----v---+ +----v---+   +-----v--+
            | mail   | | files  |   |  ...   |  first-party stdio MCP servers
            | server | | server |   |        |  spawned and owned by the broker
            +--------+ +--------+   +--------+

Claude connects to ONE endpoint (the broker). The broker is the parent process
of every server, which is what gives it real lifecycle control. Children are
plain stdio MCP servers, unmodified.

## Security model (the core; treat as the spec, not advice)

### Boundary principle
The UI is NOT the security boundary. The boundary is (a) the broker's control
channel and (b) the broker's process identity. Auth strength is proportional to
the authority a channel grants.

### Process identity
- Broker runs as a dedicated service account (e.g. `mcp-lock`), NOT the
  operator's interactive user.
- Broker owns its binary, manifest, logs, and key material. The operator's
  interactive account cannot read the manifest/secrets, edit them, or kill the
  daemon. Compromise of the operator's shell is therefore NOT compromise of the
  broker.

### Two channels
1. Control channel (clients -> broker): carries privileged actions including
   ELEVATION. Strong auth.
   - Local: Unix domain socket owned by the service account, plus peer
     code-signature verification (reject any peer not matching a registered,
     signed client identity). macOS-specific; a bonus layer where available.
   - Remote: TLS listener bound to the Tailscale interface only (never 0.0.0.0),
     mutual TLS (registered client certificate required).
2. MCP endpoint (Claude client -> broker): in default un-elevated state can only
   invoke READ tools, so it does not need the control channel's machinery.
   - v1: bearer token in the client's MCP config header. Spec-acceptable for
     internal (non-public) servers. Bind listener to loopback (local) or the
     Tailscale interface (remote). Token rotatable, never shared across
     deployments.
   - Validation MUST be a pluggable seam so OAuth 2.1 + PKCE drops in for v2
     without touching the endpoint.

### Exposure resolution (the heart of the system)
For each running, non-paused server, the tools Claude is offered are:

    exposed = readTools + (writeTools if elevation.active and not expired else [])

- Anything NOT classified is treated as WRITE (gated). Default-deny.
- On any change (elevation grant/expiry, pause, stop) the broker recomputes
  exposure and fires MCP `tools/list_changed`. The model cannot call what is not
  listed. Call-time rejection is a fallback, not the primary gate.

### Tool classification
- Operator-authoritative, defined in the broker manifest (owned by the service
  account, unwritable by the operator's interactive user).
- A server's own annotation hints (readOnlyHint etc.) are used ONLY to prefill a
  proposed classification at registration time. They are NEVER trusted as
  authoritative. The gated party does not get to redraw its own boundary.
- Manifest is integrity-hashed at load; the hash is logged.

### Elevation via presence proof
Touch ID (or platform equivalent) is NOT a token. It unlocks a per-client signing
key. Flow:
1. Client requests elevation for a server + toolset + mode + expiry.
2. Broker returns a fresh single-use nonce.
3. Biometric/passcode unlocks the client's key (Keychain item gated
   `.biometryCurrentSet` on macOS).
4. Client signs (nonce + serverId + tools + expiry).
5. Broker verifies signature against the registered public key, checks the nonce
   is fresh and unused, then flips exposure and starts a timer.

- A credential at rest is useless without a fresh nonce signature (no replay).
- Modes: `duration` (broker auto-revokes on expiry) or `until_revoked`.
  `until_revoked` is opt-in behind a loud confirmation; default to short duration.
- `confirmTools` (e.g. send_message, delete_message) require a fresh per-action
  presence confirmation EVEN during an active elevation window. Time-boxing
  shrinks the prompt-injection window; per-action confirm closes the destructive
  ones inside it.

### Presence sourcing (SSH and remote)
The broker host has a screen.
- Co-located (operator at the host): local presence prompt on the host screen.
- Remote via the GUI client on a laptop: presence happens on the laptop
  (its biometric), the signed assertion travels to the broker. Transport-agnostic.
- SSH self-use (Option A): the CLI does not present a local prompt over SSH; it
  requests the nonce and hands the signing challenge back to a small trusted
  helper on the OPERATOR's end (SSH-agent-forwarding analogue). Key never leaves
  the operator's device.
- Option C: SSH-initiated elevation can fire the presence prompt on the broker
  host's physical screen for at-the-desk approval.
- A bare SSH session with no forwarded helper and no physical screen access
  CANNOT elevate. This is the intended fail-closed property, not a limitation.

### Authority tiers for the CLI
- Observe (status, logs, list): authenticated client, no presence.
- Lifecycle (start, stop, pause, resume): no presence required. Fail-safe by
  design (start brings a server up READ-ONLY; stop reduces access). Worst case
  for a terminal attacker is denial of service, never escalation.
- Elevate: full presence gate as above.

### Lifecycle semantics
- start: spawn child, expose its read tools.
- stop: SIGTERM child, drop from aggregation, fire list_changed.
- pause: routing-level (stop exposing/routing, leave process running) so resume
  is instant and no requests hang. fire list_changed.
- resume: re-expose.

### Fail-closed invariants (encode as tests)
- Cold start: every server read-only, zero elevations, regardless of prior state.
- Elevation NEVER persists across broker restart.
- Any fault (child crash, missed timer, control-API disconnect, panic): revert
  to read-only.
- pause and stop immediately recompute exposure downward.
- confirmTools actions require a fresh presence ack even mid-elevation.
- First run is CLOSED: no baked-in token/cert/privileged mode. Privileged actions
  refused until the operator generates keys and registers a client.

### Audit
Append-only local log of every elevation (grant, expiry, revoke) and every write
tool invocation. This is the tape for incident review.

### Honest ceiling (must go in SECURITY.md verbatim in spirit)
- Defends against: scripting the control socket, flat-token theft/replay,
  manifest tampering by the operator's user, killing the daemon to reset state,
  and bare-SSH elevation attempts. Privilege separation means a compromised
  OPERATOR account does not hand over the broker.
- Does NOT defend against: arbitrary code execution AS the broker's service
  account, or injection into the signed, presence-unlocked client. No single-host
  design wins those. Do not claim otherwise.
- Independent surface: the data plane. Prompt injection rides in on email content.
  If write is elevated while Claude reads a malicious message, it can drive a
  write. Mitigated by narrow windows and confirmTools, NOT eliminated.

## Language, runtime, structure
- Broker + CLI: Rust.
- Mac UI (later): SwiftUI, native.
- Security core (credential handling, presence-nonce verification, token
  validation, exposure/classification gate) MUST be isolated into plain,
  synchronous, lifetime-light Rust that a C developer can audit on day one. Push
  async / TLS / transport complexity to the edges around it.
- Encode invariants in the type system: e.g. a `ValidatedToken` type that cannot
  be constructed from an unvalidated input, an `Elevation` that carries its
  expiry, a tool that is `Classified` before it can be exposed.

## Platform abstraction (design for now, implement Mac only)
Define traits, with macOS implementations only in v1:
- `PresenceProvider`  (macOS: LocalAuthentication; Linux: FIDO2/PAM future;
  Windows: Hello future)
- `SecureKeyStore`    (macOS: Keychain/Secure Enclave; Linux: Secret Service/TPM;
  Windows: DPAPI/TPM)
- `PeerIdentityVerifier` (macOS: code-signature over UDS; Linux: SO_PEERCRED
  uid/pid only, NO code identity; Windows: named-pipe SID)
- `ProcessSupervisor` (macOS: launchd; Linux: systemd; Windows: Service)
- `ProcessIsolator`   (v2 sandboxing seam; macOS: seatbelt; Linux: namespaces/
  seccomp; Windows: AppContainer)
The signed-nonce assertion is the PRIMARY portable presence primitive.
Peer-code-signature is a Mac-only bonus layer, never the sole gate.

## Sandboxing seam (design for now, implement in v2)
The child-spawning path MUST accept an injectable execution context
(identity, sandbox profile, scoped credentials). v1 always passes
"first-party, broker identity, no sandbox". v2 slots per-child isolation and
per-child scoped credentials in without touching the spawn path. Secrets are
scoped per child (mail server gets the IMAP password; nothing else does), never
pooled where any child could reach them.

## Client identity model (keep uniform; it is the v2 multi-user seam)
- Every client (GUI, CLI) is a registered, code-signed keypair with its own
  presence-gated key. No special-casing "local" or "it's me".
- The expected signing identity is per-deployment CONFIG, registered on first
  run, NEVER hardwired to one Apple Team ID (so source-built users work).
