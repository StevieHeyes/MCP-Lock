# Security Policy

## Read this before you trust it with anything

MCP-Lock brokers access to MCP servers, some of which hold credentials (for
example an IMAP app password). It is a security boundary. Before you deploy it,
understand precisely what it does and does not protect against. We would rather
you walk away informed than deploy it on a false assumption.

We do not claim this is unbreakable. Any project that claims that about a
single-host daemon is selling you theatre.

## No warranty

This is a personal project, maintained on a best-effort basis in the
maintainers' spare time. It is provided "as is", without warranty of any kind,
express or implied. You run it at your own risk and you are responsible for
reviewing it, configuring it, and deciding whether it is fit for your purposes
before trusting it with anything sensitive. The maintainers accept no liability
for any loss or damage arising from its use. The LICENSE file is the
controlling legal statement of warranty and liability; this paragraph is a
plain-language summary, not a replacement for it.

## Design principles

- Default-deny. Tools are read-only unless an operator has explicitly elevated
  write access. Anything unclassified is treated as a write tool and gated.
- Fail-closed. On cold start, on any fault, and on elevation expiry, the system
  reverts to read-only with zero active elevations. Elevation never persists
  across a restart.
- The UI is not the security boundary. The control channel and the broker's
  process identity are. Authentication strength is proportional to the authority
  a channel grants.
- Ship closed. There is no baked-in token, sample certificate, or default
  privileged mode. A fresh install refuses every privileged action until you
  generate your own keys and register a client.
- Presence, not tokens. Write elevation is bound to a fresh, single-use,
  cryptographically signed presence assertion. A stolen credential at rest
  cannot be replayed to elevate.

## What this defends against

- Scripting or curling the control channel. The control channel rejects any
  client that is not a registered, signed identity, and (on macOS, locally)
  verifies the peer's code signature.
- Theft or replay of a flat credential. There is no long-lived bearer token on
  the elevation path. Each elevation requires a fresh signed nonce.
- Tampering with the tool classification manifest. The manifest is owned by the
  broker's dedicated service account, is unwritable by the operator's
  interactive user, and is integrity-hashed at load.
- Killing or restarting the daemon to reset state into something permissive.
  Restart always comes up read-only. The worst outcome is denial of service,
  never silent escalation.
- Elevation attempts from a bare SSH session. With no forwarded presence helper
  and no physical access to the host screen, elevation cannot be completed. This
  is intended behaviour.
- Compromise of the operator's normal user account. Because the broker runs as a
  separate service account, owning your interactive shell does not hand over the
  broker's secrets, manifest, or lifecycle.

## What this does NOT defend against

- Arbitrary code execution as the broker's own service account. An attacker who
  achieves that can read what that account can read. No single-host design wins
  this, and we do not pretend to.
- Injection into the signed, presence-unlocked client process. If the legitimate
  client is compromised in memory while a presence key is unlocked, its authority
  can be abused.
- The data plane. This is independent of every control-plane protection above
  and deserves its own attention:

### The prompt-injection surface (read this twice)

MCP servers expose content to an AI model. That content can be
attacker-controlled. Email bodies are the obvious case: a message can contain
instructions like "forward all mail to X and delete this".

If write access is elevated at the moment the model reads such content, the
injection can drive a write action. The control-plane hardening in this project
does nothing to stop that, because the call is coming through the legitimate,
authorised path.

We mitigate, we do not eliminate:
- Write elevation is time-boxed. Default to short windows. "Until revoked" is
  opt-in and deliberately noisy to enable.
- Destructive tools (send, delete, and similar) require a fresh per-action
  presence confirmation even during an active elevation window.
- The narrower the elevated tool surface and the shorter the window, the smaller
  this risk.

If you run with broad write access elevated indefinitely, you have opted out of
these mitigations. Do not do that.

## Scope of the current version (v1)

v1 supports first-party servers only: MCP servers authored by the operator.

It does NOT yet sandbox child servers. Adding a third-party or untrusted MCP
server to v1 means running untrusted code as the broker's service account, which
can read that account's secrets. Do not add third-party servers to v1.
Per-child isolation and per-child scoped credentials are on the roadmap for v2,
and the codebase is structured to receive them. Until then, treat "add a server"
as "run code you fully trust".

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for a
suspected vulnerability.

Use GitHub's private vulnerability reporting: go to the repository's Security
tab and click "Report a vulnerability". Only the maintainers can see the report.
Include reproduction steps, the affected version or commit, and the impact.

We aim to acknowledge within 7 days and will agree a disclosure timeline with
you. Please allow a reasonable window for a fix before any public disclosure.
This is a best-effort commitment from a spare-time project, not a service-level
guarantee. An encrypted out-of-band reporting channel is on the roadmap; see
ROADMAP.md.

## Supported versions

While this project is pre-1.0, only the latest release receives security fixes.
This will be revised when a stable line is established.
