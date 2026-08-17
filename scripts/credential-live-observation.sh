#!/usr/bin/env bash
# Serial, production-safe live observations for a fresh Xidian session.
# It sends only normal client traffic to advertised resources and never injects
# malformed frames, unknown commands, transient statuses, or unapproved UDP data.
set -uo pipefail

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="$REPO/target/debug/atrust-probe"
SESSION="${HERMES_SESSION_FILE:-$HOME/.hermes/xidian-session.json}"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
TCP_TARGET="${HERMES_TCP_TARGET:-gsoft.xidian.edu.cn:443}"
L3_TARGET="${HERMES_L3_TARGET:-202.117.112.70:443}"
SHORT_HOLD="${SHORT_HOLD:-75}"
THRESHOLD_HOLD="${THRESHOLD_HOLD:-5400}"
THRESHOLD_KEEPALIVE="${THRESHOLD_KEEPALIVE:-1800}"
MAX_SESSION_AGE="${MAX_SESSION_AGE:-900}"

STAMP="$(date +%Y-%m-%d-%H%M%S)"
OUT="$REPO/debug_logs/$STAMP-credential-live"
SUMMARY="$OUT/summary.log"
mkdir -p "$OUT"
chmod 700 "$OUT"

note() {
  printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"
}

run_arm() {
  local arm="$1" budget="$2"
  shift 2
  local log="$OUT/$arm.log" started status elapsed
  started="$(date +%s)"
  note "arm=$arm state=start budget_seconds=$budget"
  env HERMES_LOG=info,atrust_l3=debug,atrust_tcp=debug \
    timeout --signal=TERM --kill-after=10 "$budget" "$@" >>"$log" 2>&1
  status=$?
  elapsed=$(( $(date +%s) - started ))
  note "arm=$arm state=finish exit=$status elapsed_seconds=$elapsed log=$log"
  return "$status"
}

abort() {
  note "experiment=credential-live result=aborted reason=$1"
  exit 1
}

count_events() {
  local pattern="$1" file="$2" count
  count="$(rg -c "$pattern" "$file" 2>/dev/null || true)"
  printf '%s' "${count:-0}"
}

summarize_l3_arm() {
  local arm="$1"
  local log="$OUT/$arm.log"
  [[ -f "$log" ]] || return
  note "arm=$arm observation=wire transient_auth=$(count_events 'transient_statuses_received=[1-9]|auth_unattributable.*status=13[2-5]' "$log") second_vip=$(count_events 'session.second_vip_resp' "$log") data_length_prefixed=$(count_events 'length_prefixed' "$log") data_token_framed=$(count_events 'token_framed' "$log") protocol_messages=$(count_events 'session.protocol_message' "$log") unknown_commands=$(count_events 'session.ignored_command' "$log")"
}

note "experiment=credential-live state=start"
note "gateway=$GATEWAY node=$NODE tcp_target=$TCP_TARGET l3_target=$L3_TARGET"
note "short_hold_seconds=$SHORT_HOLD threshold_hold_seconds=$THRESHOLD_HOLD threshold_keepalive_seconds=$THRESHOLD_KEEPALIVE"

[[ -x "$PROBE" ]] || abort "probe_missing"
[[ -f "$SESSION" ]] || abort "session_missing"
[[ "$(stat -c %a "$SESSION")" == "600" ]] || abort "session_mode_not_0600"
session_age=$(( $(date +%s) - $(stat -c %Y "$SESSION") ))
(( session_age >= 0 && session_age <= MAX_SESSION_AGE )) || abort "session_not_fresh"
note "session_age_seconds=$session_age session_mode=0600"

run_arm "b0-session-check" 180 "$PROBE" --host "$GATEWAY" \
  session-check --session-file "$SESSION" || abort "initial_session_check_failed"

run_arm "resource-snapshot" 180 "$PROBE" --host "$GATEWAY" \
  client-resource --session-file "$SESSION" \
  --save-body "$OUT/client-resource.json" || abort "resource_snapshot_failed"
chmod 600 "$OUT/client-resource.json"

run_arm "b0-tcp-https" 120 "$PROBE" --host "$GATEWAY" --insecure-tls \
  tcp-dial --session-file "$SESSION" --node "$NODE" --skip-node-probe \
  --target "$TCP_TARGET" --send-https --application-timeout-seconds 30 \
  --connect-timeout-seconds 20 --handshake-timeout-seconds 20 \
  || abort "initial_tcp_baseline_failed"

# E15 live observation: the first arm is command-idle apart from heartbeat;
# the second writes one ordinary authorized data packet every 20 seconds.
run_arm "e15-idle" $((SHORT_HOLD + 180)) "$PROBE" \
  --host "$GATEWAY" --insecure-tls l3-session \
  --session-file "$SESSION" --node "$NODE" --target "$L3_TARGET" \
  --probe tcp-syn --auth-only --src-port 47100 \
  --hold-seconds "$SHORT_HOLD" --heartbeat-seconds 25 \
  --status-interval-seconds 10 --resource-refresh-seconds 3600 \
  --connect-timeout-seconds 20 || note "arm=e15-idle candidate_failed=true"

run_arm "e15-active" $((SHORT_HOLD + 180)) "$PROBE" \
  --host "$GATEWAY" --insecure-tls l3-session \
  --session-file "$SESSION" --node "$NODE" --target "$L3_TARGET" \
  --probe tcp-syn --auth-only --src-port 47200 \
  --hold-seconds "$SHORT_HOLD" --heartbeat-seconds 25 \
  --status-interval-seconds 10 --data-keepalive-seconds 20 \
  --resource-refresh-seconds 3600 --connect-timeout-seconds 20 \
  || note "arm=e15-active candidate_failed=true"

# E7 midpoint follow-up and passive E12/E17/E18 observation. A successful
# 1800-second keepalive arm narrows the known data-idle threshold upward from
# 60 seconds without opening concurrent sessions on the same device identity.
run_arm "e7-threshold-1800" $((THRESHOLD_HOLD + 600)) "$PROBE" \
  --host "$GATEWAY" --insecure-tls l3-session \
  --session-file "$SESSION" --node "$NODE" --target "$L3_TARGET" \
  --probe tcp-syn --auth-only --src-port 47300 \
  --hold-seconds "$THRESHOLD_HOLD" --heartbeat-seconds 25 \
  --status-interval-seconds 60 \
  --data-keepalive-seconds "$THRESHOLD_KEEPALIVE" \
  --resource-refresh-seconds 60 --connect-timeout-seconds 20 \
  || note "arm=e7-threshold-1800 candidate_failed=true"

run_arm "b0-final-session-check" 180 "$PROBE" --host "$GATEWAY" \
  session-check --session-file "$SESSION" \
  || note "arm=b0-final-session-check baseline_failed=true"

run_arm "b0-final-tcp-https" 120 "$PROBE" --host "$GATEWAY" --insecure-tls \
  tcp-dial --session-file "$SESSION" --node "$NODE" --skip-node-probe \
  --target "$TCP_TARGET" --send-https --application-timeout-seconds 30 \
  --connect-timeout-seconds 20 --handshake-timeout-seconds 20 \
  || note "arm=b0-final-tcp-https baseline_failed=true"

summarize_l3_arm "e15-idle"
summarize_l3_arm "e15-active"
summarize_l3_arm "e7-threshold-1800"
note "experiment=credential-live state=finished"
note "interpretation=inspect_baseline_flags_before_attributing_candidates"
