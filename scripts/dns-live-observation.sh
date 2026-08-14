#!/usr/bin/env bash
# Controlled DNS queries through an already authenticated Xidian L3 session.
# This sends only ordinary DNS wire queries and records metadata, not answers.
set -uo pipefail

REPO="${REPO:-/home/nancunchild/projects/Hermes}"
PROBE="$REPO/target/debug/atrust-probe"
SESSION="${HERMES_SESSION_FILE:-$HOME/.hermes/xidian-session.json}"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
OUT="$REPO/debug_logs/$(date +%Y-%m-%d-%H%M%S)-dns-live"
mkdir -p "$OUT"
chmod 700 "$OUT"

note() {
  printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$OUT/summary.log"
}

fail() {
  note "experiment=dns-live result=aborted reason=$1"
  exit 1
}

[[ -x "$PROBE" ]] || fail "probe_missing"
"$PROBE" --host invalid l3-session --help 2>&1 | rg -q -- "--dns-name" \
  || fail "probe_binary_stale"
[[ -f "$SESSION" ]] || fail "session_missing"
[[ "$(stat -c %a "$SESSION")" == "600" ]] || fail "session_mode_not_0600"
age=$(( $(date +%s) - $(stat -c %Y "$SESSION") ))
(( age >= 0 && age <= 900 )) || fail "session_not_fresh"

note "experiment=dns-live state=start session_age_seconds=$age node=$NODE"

run_query() {
  local label="$1" target="$2" name="$3" extra="${4:-}"
  local log="$OUT/$label.log" status
  note "query=$label target=$target name=$name type=${extra:-A} state=start"
  # shellcheck disable=SC2086
  HERMES_LOG=info timeout --signal=TERM --kill-after=10 180 "$PROBE" \
    --host "$GATEWAY" --insecure-tls --log-file "$log" \
    l3-session --session-file "$SESSION" --node "$NODE" \
    --target "$target" --probe udp --dns-name "$name" $extra \
    --src-port "$((40000 + ${#label}))" --reply-timeout-seconds 10 \
    --connect-timeout-seconds 20 --resource-refresh-seconds 3600
  status=$?
  note "query=$label state=finish exit=$status log=$log"
  return 0
}

# ANY is intentionally first because it may be larger or truncated.
run_query "dns-any-xidian" "202.117.112.3:53" "xidian.edu.cn" "--dns-any"
run_query "dns-a-www" "202.117.112.3:53" "www.xidian.edu.cn"
run_query "dns-a-gsoft" "202.117.112.3:53" "gsoft.xidian.edu.cn"
run_query "dns-a-w" "202.117.112.3:53" "w.xidian.edu.cn"
run_query "dns-a-zfw" "202.117.112.3:53" "zfw.xidian.edu.cn"

# Cross-check the advertised DNS range with one ordinary A query per endpoint.
for octet in 9 10 11 12 13 14; do
  run_query "dns-a-${octet}" "202.117.112.${octet}:53" "www.xidian.edu.cn"
done

note "experiment=dns-live state=finished"
