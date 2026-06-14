# Contributing

Thanks for your interest. This is a personal project maintained on a best-effort
basis in spare time. Contributions are welcome, but there is no obligation to
respond on any timeline, to accept any change, or to fix any issue. Please read
this before opening an issue or pull request.

## Licensing of contributions

This project is licensed under the Apache License, Version 2.0. By submitting a
contribution you agree that it is licensed under the same terms (inbound equals
outbound). Do not submit code you do not have the right to license this way.

We use the Developer Certificate of Origin (DCO). Sign off every commit with:

    git commit -s

This adds a `Signed-off-by` line asserting that you wrote the change or otherwise
have the right to submit it under the project license. Commits without sign-off
will not be merged.

## Before you start

- For anything non-trivial, open an issue first to discuss the approach. This
  avoids wasted effort on a change that may not fit the design.
- Read [docs/DESIGN.md](docs/DESIGN.md). The architecture and, especially, the
  security model are deliberate. Changes that cut against them need a strong case.
- Do NOT report security vulnerabilities here. See [SECURITY.md](SECURITY.md) for
  the private reporting process. Never put a vulnerability in a public issue or
  pull request.

## Pull request requirements

- One logical change per pull request. Keep them small and reviewable.
- Use Conventional Commits for commit messages.
- The PR description must state: what changed, how to test it, what could break,
  and how to roll it back.
- CI must be green before a PR is considered ready: formatting (rustfmt), lints
  (clippy, warnings denied), tests, dependency audit (cargo-deny / cargo-audit),
  and secret scanning.
- Update the relevant documentation (README, DESIGN, ROADMAP, SECURITY) in the
  same PR when behaviour or design changes.

## Security-sensitive changes

The security core (credential handling, presence and nonce verification, token
validation, the exposure/classification gate, and the fail-closed logic) is held
to a higher bar.

- Flag any change touching the security core clearly in the PR title and
  description, and explain exactly what a reviewer should check and why.
- Keep security-core code plain, synchronous, and lifetime-light Rust so it can
  be audited without deep Rust fluency. Push async, TLS, and transport complexity
  to the edges around it.
- Do not weaken a fail-closed or default-deny invariant without an explicit
  discussion in an issue first. The invariants in DESIGN.md are tests, not
  suggestions.
- Never include real credentials in code, tests, or fixtures. Use test doubles
  and placeholders. PRs that add real secrets will be rejected and the secret
  treated as compromised.

## Decisions not covered by the design

If you hit a design or security decision that DESIGN.md does not settle, do not
guess. Open an issue titled `[DECISION]` describing the options and their
tradeoffs, and let it be discussed before building on it.

## Code style

- Rust: rustfmt for formatting, clippy for lints. Match the existing style.
- Prefer boring, maintainable, production-safe code over clever code.
- Do not add a new dependency, service, or major abstraction without justifying
  it in the PR description. Prefer the standard library and well-audited crates.
