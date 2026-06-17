# Prompts log

A record of the prompts that actually triggered build work or delivery on
MCP-Lock. This project is built with heavy use of an AI coding agent; this log
exists for provenance and reproducibility, so anyone (including future
maintainers) can see what drove each piece of work.

## Rules for this file

- **Log only delivery-triggering prompts.** Record prompts that caused build
  work or a deliverable (kickoff, slice directives, re-prompts that changed the
  build). Do NOT log conversational, clarifying, or exploratory messages.
- **Never include secrets.** No credentials, tokens, API keys, private hostnames,
  or other sensitive context. Redact before logging. This file is public.
- **Verbatim where practical.** Record the prompt as given, minus redactions.
  Mark any redaction clearly as `[REDACTED: reason]`.
- **Append-only.** Add new entries; do not rewrite or delete past entries. The
  log is a history, not a current-state document.
- **Link the outcome.** Where possible, reference the resulting PR or commit so a
  reader can connect prompt to delivery.

## Entry template

```
## YYYY-MM-DD — <short label> (Slice N, if applicable)
- Author: <who gave the prompt>
- Purpose: <one line: what this prompt was meant to produce>
- Outcome: <PR #, commit hash, or "in progress">

Prompt:
~~~
<verbatim prompt text, with any [REDACTED: reason] markers>
~~~
```

---

## 2026-06-14 — v1 build kickoff (Slice 0 onward)
- Author: operator
- Purpose: Initiate the v1 build as a sequence of reviewable PR slices.
- Outcome: in progress

Prompt:
~~~
You are building v1 of MCP-Lock. The full specification is in docs/DESIGN.md.
Read it fully before doing anything, and treat it as authoritative. This message
sets HOW you work; the doc sets WHAT you build.

PROVIDED DOCS ARE AUTHORITATIVE
README.md, docs/DESIGN.md, SECURITY.md, ROADMAP.md, CONTRIBUTING.md, and
docs/prompts.md are provided by the operator and already in the repo. Use them
verbatim. Do NOT rewrite, reword, "improve", or soften any of their content,
especially the security and no-warranty language. The ONLY edits you may make to
these files are: filling the sections in README.md explicitly marked TODO(agent),
and only as the corresponding build slice lands; and APPENDING new entries to
docs/prompts.md (never altering existing entries). If you believe any provided
doc is wrong, do not edit it: open a GitHub issue titled [DECISION] and continue.

MISSION
Build v1 as a sequence of small, independently working vertical slices, each
landing as its own pull request with a clear, phone-readable description. Optimise
for "partial completion is still valuable": earlier slices must work and be
committed before later ones begin.

HARD CONSTRAINTS (non-negotiable)
1. This is a security boundary. You do NOT have authority to merge it. Open every
   slice as a PR against main on a feature branch. Never push to main. Never
   self-merge. The human reviews and merges.
2. Security-critical code (anything in the security core: credential handling,
   presence/nonce verification, token validation, exposure/classification gate,
   fail-closed logic) must be in its own PR(s), titled with the prefix
   [SECURITY-REVIEW], with a description that walks a reviewer through exactly
   what to check and why. Keep this code plain, synchronous, lifetime-light Rust.
3. No real credentials, ever. Use test fixtures, env placeholders, and a local
   fake/IMAP test double. Never prompt for or store a real password. Add secret-
   scanning to CI.
4. Do not invent security mechanisms. If a decision is needed that the doc does
   not cover, do NOT guess: open a GitHub issue titled [DECISION] describing the
   options and tradeoffs, then continue with slices that are not blocked by it.
5. Rust for broker and CLI. Boring, maintainable, production-safe over clever.
   No new dependency without justifying it in the PR description; prefer the std
   library and well-audited crates. Run cargo-deny/cargo-audit in CI.

NAMING (use consistently)
- Project / display name: MCP-Lock
- Daemon binary/crate: mcp-lockd
- CLI binary/command: mcp-lock
- Dedicated service account referenced in design: mcp-lock

REPO PRACTICES
- Conventional commits. One logical change per commit.
- Every PR description states: what changed, how to test it, what could break,
  how to roll it back. (This is how the human reviews from a phone.)
- CI (GitHub Actions) green before a PR is "ready": fmt, clippy (deny warnings),
  test, cargo-deny, secret scan.
- Tests encode the fail-closed invariants from the doc as first-class test cases.
- Keep docs/DESIGN.md, SECURITY.md, ROADMAP.md, README.md current as you go,
  subject to the "provided docs are authoritative" rule above.
- Maintain docs/prompts.md: when the operator gives a prompt that triggers build
  work or delivery, append it verbatim (per that file's rules and template) in
  the same PR as the resulting work. Log only delivery-triggering prompts, never
  conversational ones, and never include secrets.

BUILD ORDER (each a PR; do not start the next until the current one is green)
Slice 0  Repo scaffolding: Rust workspace (crates: core, transport, broker, cli),
         CI pipeline, .gitignore. LICENSE: place the standard, unmodified Apache
         License 2.0 text in LICENSE, and add a NOTICE file (operator-provided
         content). Confirm the operator-provided docs (README.md, docs/DESIGN.md,
         SECURITY.md, ROADMAP.md, CONTRIBUTING.md, docs/prompts.md) are present
         and do not alter them beyond the rules above. Define the platform-
         abstraction traits and the sandbox/execution-context seam as interfaces
         with macOS-only stubs.
Slice 1  Read-only IMAP mail MCP server (stdio): search, list_messages,
         fetch_message. Standalone and runnable directly against a Claude client
         WITHOUT the broker. Credentials via env/Keychain placeholder; test
         against a fake IMAP fixture. This is the first usable deliverable.
Slice 2  [SECURITY-REVIEW] Broker core: manifest loading + integrity hash,
         classification (hint-as-prefill, operator-authoritative, default-gated),
         exposure resolution, fail-closed invariants + their tests. No real
         transport yet; drive via unit/integration tests.
Slice 3  Broker aggregator + MCP endpoint: spawn/supervise child stdio servers
         (broker as parent), aggregate tools, bearer-token auth as a PLUGGABLE
         validation seam, tools/list_changed on exposure change. Adopt the Slice 1
         mail server via manifest config (no rewrite).
Slice 4  CLI (mcp-lock): observe (status/logs/list) + lifecycle (start/stop/pause/
         resume) over the control channel. Lifecycle requires no presence.
Slice 5  [SECURITY-REVIEW] Control channel + presence/elevation: UDS local with
         peer-identity check, elevation protocol (nonce -> signed assertion ->
         verify -> time-boxed exposure flip), confirmTools per-action gate,
         audit log. Wire to the SecureKeyStore trait, NOT to a real Keychain item
         holding real secrets. Leave end-to-end Keychain wiring and the remote
         mTLS/Tailscale listener as documented follow-ups for human setup.

DEFERRED (do not attempt this session): SwiftUI UI, real-credential end-to-end on
the host, remote mTLS listener hardening. Note these as issues.

START by reading docs/DESIGN.md, then open Slice 0 as a PR. Report progress in PR
descriptions so it can be reviewed asynchronously.
~~~
