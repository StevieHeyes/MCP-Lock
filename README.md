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

<!-- TODO(agent): complete once Slice 0/1 land. Document the Rust toolchain
requirement, build command (cargo build --release), and where the binaries are
produced. Do not document install steps for components that do not yet exist. -->

_Not yet available. This section will be completed as the first build slices
land._

## Usage

<!-- TODO(agent): complete as slices land. Cover, in order of availability:
running the read-only mail server standalone (Slice 1); running the broker and
registering the mail server via manifest (Slice 3); the CLI observe/lifecycle
commands (Slice 4); and the elevation flow (Slice 5). Keep examples accurate to
shipped behaviour only. -->

_Not yet available. This section will be completed as the build progresses._

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Note that security-sensitive changes
receive extra scrutiny and that security issues must be reported privately, never
in a public issue or pull request.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Contributions are accepted under the same license (see
CONTRIBUTING.md).
