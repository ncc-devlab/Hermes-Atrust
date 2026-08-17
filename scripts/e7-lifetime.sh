#!/usr/bin/env bash
#
# E7 follow-up: is the ~55-58 minute L3 connection lifetime an idle timeout or an
# absolute limit?
#
# Every long run so far used --auth-only and therefore never sent a single 0x14
# data frame, which makes the two explanations indistinguishable. The arms below
# are run one at a time, not concurrently: two live L3 sessions on one SID would
# add a variable the gateway's behaviour is not known to be independent of.
#
#   B  treatment   target T, data keepalive every 60s
#   A  control     target T, data-idle            <- only keepalive differs from B
#   C  generality  target T2 (different appId), keepalive
#
# A is what makes B readable, so it runs even if B is inconclusive. C only adds
# value when B survived, so it is skipped otherwise.
#
# Readout:
#   B and A both end near ~3400s  -> absolute lifetime, keepalive is irrelevant
#   B reaches HOLD, A ends ~3400s -> idle timeout, and the keepalive defeats it
#   both end far below ~3400s     -> something else changed; compare with the
#                                    2026-08-04 samples before drawing anything
set -uo pipefail

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="$REPO/target/debug/atrust-probe"
SESSION="${HERMES_SESSION_FILE:-$HOME/.hermes/xidian-session.json}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"

# 2.5h. The known lifetime is ~57min, so reaching this is a 2.5x margin — enough
# to call it "not bounded near an hour" without running all night.
HOLD="${HOLD:-9000}"
KEEPALIVE="${KEEPALIVE:-60}"
TARGET_A="${TARGET_A:-202.117.112.71:8081}"
TARGET_C="${TARGET_C:-202.117.124.116:443}"

STAMP="$(date +%Y-%m-%d)"
OUT="$REPO/debug_logs"
SUMMARY="$OUT/$STAMP-e7-lifetime-summary.txt"

mkdir -p "$OUT"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }

# $1 arm, $2 target, $3 keepalive seconds, $4 source port
run_arm() {
  local arm="$1" target="$2" keepalive="$3" src_port="$4"
  local log="$OUT/$STAMP-e7-$arm.log"
  local started elapsed status

  note "arm=$arm target=$target keepalive=${keepalive}s hold=${HOLD}s log=$(basename "$log")"
  started=$(date +%s)

  HERMES_LOG=info,atrust_l3=debug timeout $((HOLD + 600)) "$PROBE" \
    --host "$GATEWAY" --insecure-tls --log-file "$log" \
    l3-session --session-file "$SESSION" --node "$NODE" \
    --target "$target" --probe tcp-syn --auth-only \
    --src-port "$src_port" \
    --hold-seconds "$HOLD" --heartbeat-seconds 25 \
    --status-interval-seconds 60 \
    --data-keepalive-seconds "$keepalive" \
    --resource-refresh-seconds 20000 \
    --connect-timeout-seconds 20 >>"$log" 2>&1
  status=$?
  elapsed=$(( $(date +%s) - started ))

  # The probe exits non-zero when the gateway closes during the hold, which is
  # the measurement — not a failure of the run.
  note "arm=$arm ended after ${elapsed}s exit=$status"
  note "arm=$arm last_sample=$(grep -a 'probe.e7.sample' "$log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-400)"
  note "arm=$arm protocol_messages=$(grep -ac 'session.protocol_message' "$log" || true)"

  ARM_ELAPSED=$elapsed
}

note "=== E7 lifetime experiment start (hold=${HOLD}s) ==="
note "node=$NODE session=$(basename "$SESSION")"

run_arm "b-keepalive" "$TARGET_A" "$KEEPALIVE" 46000
B_ELAPSED=$ARM_ELAPSED

run_arm "a-idle" "$TARGET_A" 0 47000
A_ELAPSED=$ARM_ELAPSED

if [ "$B_ELAPSED" -ge $((HOLD - 120)) ]; then
  note "B reached the hold; running C to check the result is not target-specific"
  run_arm "c-keepalive-other-target" "$TARGET_C" "$KEEPALIVE" 48000
else
  note "B ended early (${B_ELAPSED}s); skipping C, it would not be interpretable"
fi

note "=== summary: b_keepalive=${B_ELAPSED}s a_idle=${A_ELAPSED}s hold=${HOLD}s ==="
note "reminder: a same-day A control is what makes B readable; do not cite B alone"
