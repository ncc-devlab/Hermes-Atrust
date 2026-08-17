#!/usr/bin/env bash
#
# E7 follow-up 2: where in (60s, ~3600s] is the L3 data-idle threshold, and does
# inbound data renew it too?
#
# 2026-08-06 established that the ~61 minute close is a data-idle timeout, that
# heartbeats do not reset it, and that outbound 0x14 every 60s holds a session
# for at least 2.5h. Two things are still open:
#
#   1. the threshold itself, only bounded to (60s, ~3600s];
#   2. whether inbound data renews it — the 2.5h arm saw data_resp = 0
#      throughout, so only the outbound direction was ever exercised.
#
# Why parallel, when the first experiment was deliberately sequential: the
# control-plane SID lives only ~3h48m (B7). A sequential sweep of four intervals
# needs 4-5 hours and therefore cannot complete inside one login — its tail arms
# would die of SID expiry, exactly as arm C did. Parallel is the only way to get
# a self-consistent dataset from one session.
#
# Concurrent L3 sessions on one SID have never been exercised (E8 tested
# concurrent flows inside ONE session). So the batch is made self-diagnosing:
#
#   guard-60   60s keepalive, proven to survive 2.5h sequentially.
#              If THIS dies, concurrency is the problem and the batch is void.
#   idle-0     no keepalive, expected to die at ~61 min. Confirms the timer.
#   k-300/900/1800   the sweep.
#   inbound-60 60s keepalive against a host known to answer, to see whether
#              data_resp > 0 and whether that changes anything.
#
# Readout:
#   arms die by interval, guard survives -> real threshold, bisect further
#   arms die together regardless of interval, guard dies -> concurrency artifact
#   guard survives but VIPs collide across arms -> re-run sequentially
set -uo pipefail

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="$REPO/target/debug/atrust-probe"
SESSION="${HERMES_SESSION_FILE:-$HOME/.hermes/xidian-session.json}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"

# 1.5h: long enough to clear the ~61min death point with margin, short enough to
# finish well inside the ~3h48m SID lifetime.
HOLD="${HOLD:-5400}"
TARGET="${TARGET:-202.117.112.71:8081}"
# gsoft.xidian.edu.cn's own address, L3-authorized on 443 (appId 2f206920) and
# known live: a TCP-tunnel GET returned HTTP 200 / 67KB on 2026-08-05. A SYN here
# should draw a SYN/ACK, which is the only way to get inbound 0x94 on this path.
TARGET_INBOUND="${TARGET_INBOUND:-202.117.112.70:443}"

STAMP="$(date +%Y-%m-%d-%H%M)"
OUT="$REPO/debug_logs"
SUMMARY="$OUT/$STAMP-e7-threshold-summary.txt"
mkdir -p "$OUT"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }

# $1 arm  $2 keepalive  $3 src port  $4 target
start_arm() {
  local arm="$1" keepalive="$2" src_port="$3" target="$4"
  local log="$OUT/$STAMP-e7-$arm.log"
  (
    local started elapsed status
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
    printf '%s arm=%s keepalive=%ss target=%s ended=%ss exit=%s vip=%s inbound_data_frames=%s\n' \
      "$(date -Is)" "$arm" "$keepalive" "$target" "$elapsed" "$status" \
      "$(grep -ao 'vip: [0-9.]*' "$log" | head -1 | cut -d' ' -f2)" \
      "$(grep -ac 'session.data_resp' "$log" || true)" >>"$SUMMARY"
  ) &
}

note "=== E7 idle-threshold sweep start (hold=${HOLD}s, parallel) ==="
note "node=$NODE target=$TARGET inbound_target=$TARGET_INBOUND"

# Staggered so the batch is not a thundering herd and deaths stay distinguishable.
start_arm "guard-60"   60   50000 "$TARGET";          sleep 20
start_arm "idle-0"     0    50100 "$TARGET";          sleep 20
start_arm "k-300"      300  50200 "$TARGET";          sleep 20
start_arm "k-900"      900  50300 "$TARGET";          sleep 20
start_arm "k-1800"     1800 50400 "$TARGET";          sleep 20
start_arm "inbound-60" 60   50500 "$TARGET_INBOUND"

note "all arms started; waiting"
wait
note "=== all arms finished ==="
note "check first: did guard-60 reach ${HOLD}s? if not, the batch is void (concurrency)"
note "check second: are the VIPs distinct across arms? if not, re-run sequentially"
