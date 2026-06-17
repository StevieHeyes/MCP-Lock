#!/usr/bin/env bash
#
# local-smoke.sh — self-contained local exercise of the MCP-Lock control plane.
#
# Stands up a real `mcp-lockd` broker over a real Unix control socket, supervising
# the read-only mail child in its credential-free `--fake` mode (no network, no
# IMAP account). Generates a fresh ed25519 operator keypair, then drives the
# control CLI through the full fail-closed → elevate → revoke cycle, asserting the
# exposure gate flips correctly at each step.
#
# Nothing here touches your real config, the default control socket, or the
# default listen port — everything lives under a throwaway temp dir and is torn
# down on exit. It makes no changes to the repo and is independent of CI.
#
# The test manifest deliberately classifies the mail child's three real read
# tools across all three policy tiers (read / write / confirm) purely to exercise
# the exposure gate — it is NOT a claim about what those tools actually do.
#
#   search        -> read     (always exposed)
#   list_messages -> write    (exposed only while elevated)
#   fetch_message -> confirm  (exposed only while elevated; call-time confirm gate)
#
# Usage:  scripts/local-smoke.sh
# Requires: cargo, openssl (3.x), xxd  — all present on a stock macOS dev box.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- preflight ---------------------------------------------------------------
for tool in cargo openssl xxd; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: '$tool' not found on PATH" >&2; exit 1; }
done

# Short temp root: macOS Unix-socket paths are capped (~104 bytes), and $TMPDIR
# is long, so we anchor under /tmp to stay well clear of the limit.
WORK="$(mktemp -d /tmp/mcplock-smoke.XXXXXX)"
LOG="$WORK/broker.log"
BROKER_PID=""

cleanup() {
  [ -n "$BROKER_PID" ] && kill "$BROKER_PID" >/dev/null 2>&1 || true
  [ -n "$BROKER_PID" ] && wait "$BROKER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; echo; echo "---- broker log ----"; cat "$LOG" 2>/dev/null; exit 1; }

# --- build -------------------------------------------------------------------
say "Building workspace (debug)"
cargo build -q --workspace
BIN_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug"
LOCKD="$BIN_DIR/mcp-lockd"
LOCK="$BIN_DIR/mcp-lock"
MAIL="$BIN_DIR/mcp-lock-mail"
for b in "$LOCKD" "$LOCK" "$MAIL"; do
  [ -x "$b" ] || fail "expected binary not found: $b"
done
ok "binaries built: mcp-lockd, mcp-lock, mcp-lock-mail"

# --- operator keypair (dev signing path, issue #13) --------------------------
say "Generating ed25519 operator keypair"
openssl genpkey -algorithm ed25519 -out "$WORK/op.pem" 2>/dev/null
SEED="$(openssl pkey -in "$WORK/op.pem" -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)"
PUB="$(openssl pkey -in "$WORK/op.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64)"
[ "${#SEED}" -eq 64 ] && [ "${#PUB}" -eq 64 ] || fail "key extraction produced wrong length"
rm -f "$WORK/op.pem"
# ed25519 is deterministic (RFC 8032): the seed below fully determines the pubkey
# the broker registers, so the dalek-side signature will verify against it.
printf '{ "operator": "%s" }\n' "$PUB" > "$WORK/clients.json"
ok "keypair generated; operator pubkey registered in clients.json"

# --- test manifest -----------------------------------------------------------
say "Writing test manifest (mail child in --fake mode)"
cat > "$WORK/manifest.json" <<JSON
{
  "servers": [
    {
      "id": "mail",
      "command": "$MAIL",
      "args": ["--fake"],
      "env": {},
      "tools": {
        "search": "read",
        "list_messages": "write",
        "fetch_message": "confirm"
      }
    }
  ]
}
JSON
ok "manifest written: $WORK/manifest.json"

# --- broker environment ------------------------------------------------------
export MCPLOCK_BEARER_TOKEN="$(openssl rand -hex 32)"
export MCPLOCK_LISTEN="127.0.0.1:8788"        # non-default port; avoids clashing with a real broker
export MCPLOCK_CONTROL_SOCK="$WORK/control.sock"
export MCPLOCK_CLIENTS="$WORK/clients.json"
export MCPLOCK_AUDIT_LOG="$WORK/audit.log"
# CLI signing identity (must match the registered pubkey above).
export MCPLOCK_CLIENT_ID="operator"
export MCPLOCK_SIGNING_KEY="$SEED"

# --- start broker ------------------------------------------------------------
say "Starting broker"
"$LOCKD" serve --manifest "$WORK/manifest.json" >"$LOG" 2>&1 &
BROKER_PID=$!

# Wait for the control socket to appear (broker bound + child handshaked).
for _ in $(seq 1 50); do
  [ -S "$MCPLOCK_CONTROL_SOCK" ] && break
  kill -0 "$BROKER_PID" 2>/dev/null || fail "broker exited during startup"
  sleep 0.1
done
[ -S "$MCPLOCK_CONTROL_SOCK" ] || fail "control socket never appeared"
ok "broker up; control socket live (pid $BROKER_PID, MCP endpoint on $MCPLOCK_LISTEN)"

# helper: assert that `mcp-lock list` output matches an exact sorted tool set
assert_tools() {
  local label="$1"; shift
  local want="$*"
  local got
  got="$("$LOCK" list | sort | tr '\n' ' ' | sed 's/ *$//')"
  want="$(printf '%s\n' $want | sort | tr '\n' ' ' | sed 's/ *$//')"
  if [ "$got" = "$want" ]; then
    ok "$label — exposed: [${got:-<none>}]"
  else
    echo "  expected: [$want]"
    echo "  got:      [$got]"
    fail "$label"
  fi
}

# --- 1. fail-closed default --------------------------------------------------
say "1. Default posture (no elevation) — expect read-only"
"$LOCK" status
assert_tools "read-only by default" "mail.search"

# --- 2. elevate --------------------------------------------------------------
say "2. Elevate 'mail' (60s TTL) — signs broker challenge with operator key"
"$LOCK" elevate mail --ttl 60
assert_tools "write+confirm tools exposed while elevated" \
  "mail.search" "mail.list_messages" "mail.fetch_message"

# --- 3. revoke ---------------------------------------------------------------
say "3. Revoke 'mail' — expect immediate drop back to read-only"
"$LOCK" revoke mail
assert_tools "back to read-only after revoke" "mail.search"

# --- 4. audit tape -----------------------------------------------------------
say "4. Audit log (elevation + revocation should be recorded)"
if [ -s "$MCPLOCK_AUDIT_LOG" ]; then
  cat "$MCPLOCK_AUDIT_LOG"
  ok "audit entries written to $MCPLOCK_AUDIT_LOG"
else
  echo "  (audit log empty — nothing recorded)"
fi

say "ALL CHECKS PASSED"
echo "Broker log: $LOG (removed on exit)"
