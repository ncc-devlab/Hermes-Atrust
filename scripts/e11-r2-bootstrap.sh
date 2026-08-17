#!/usr/bin/env bash
# E11 R2 T0: one interactive CAS/MFA login into a dedicated persistent profile.
set -euo pipefail

umask 077

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="${PROBE:-$REPO/target/debug/atrust-probe}"
RUN_DIR="${HERMES_E11_R2_RUN_DIR:-$HOME/.hermes/e11-r2}"
PROFILE="${HERMES_E11_R2_PROFILE:-$RUN_DIR/browser-profile}"
S0="${HERMES_E11_R2_S0:-$RUN_DIR/S0.json}"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
LOGIN_DOMAIN="${HERMES_LOGIN_DOMAIN:-cas42187}"
WEBDRIVER_PORT="${HERMES_E11_R2_BOOTSTRAP_WEBDRIVER_PORT:-9516}"
CHROMEDRIVER="${CHROMEDRIVER:-$HOME/.local/bin/chromedriver}"
TRACE="$RUN_DIR/bootstrap-browser-trace.jsonl"
LOG="$RUN_DIR/bootstrap.log"
OUTPUT="$RUN_DIR/bootstrap-output.log"
SUMMARY="$RUN_DIR/summary.log"

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"
touch "$LOG" "$OUTPUT" "$SUMMARY"
chmod 600 "$LOG" "$OUTPUT" "$SUMMARY"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }

if [[ ! -x "$PROBE" ]]; then
    note "phase=bootstrap outcome=precondition_failed reason=probe_missing"
    exit 1
fi
if [[ -e "$S0" ]]; then
    note "phase=bootstrap outcome=precondition_failed reason=S0_already_exists"
    exit 1
fi
if [[ -e "$PROFILE" ]]; then
    note "phase=bootstrap outcome=precondition_failed reason=profile_already_exists"
    exit 1
fi
if [[ ! -x "$CHROMEDRIVER" ]]; then
    CHROMEDRIVER=$(command -v chromedriver 2>/dev/null || true)
fi
if [[ -z "$CHROMEDRIVER" || ! -x "$CHROMEDRIVER" ]]; then
    note "phase=bootstrap outcome=precondition_failed reason=chromedriver_missing"
    exit 1
fi

mkdir -p "$PROFILE"
chmod 700 "$PROFILE"

"$CHROMEDRIVER" --port="$WEBDRIVER_PORT" --log-path="$RUN_DIR/bootstrap-chromedriver.log" \
    >"$RUN_DIR/bootstrap-chromedriver-output.log" 2>&1 &
driver_pid=$!
cleanup() {
    kill "$driver_pid" 2>/dev/null || true
    wait "$driver_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
sleep 1
if ! kill -0 "$driver_pid" 2>/dev/null; then
    note "phase=bootstrap outcome=precondition_failed reason=chromedriver_start_failed"
    exit 1
fi

note "phase=bootstrap status=waiting_for_manual_CAS_MFA profile=$PROFILE"
if ! HERMES_LOG=info HERMES_CHROME_USER_DATA_DIR="$PROFILE" \
    "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$LOG" \
    --browser-trace-file "$TRACE" cas-login --login-domain "$LOGIN_DOMAIN" \
    --webdriver-url "http://127.0.0.1:$WEBDRIVER_PORT" --timeout-seconds 1800 \
    --session-file "$S0" --get-ip-node "$NODE" --get-ip-timeout-seconds 20 \
    >>"$OUTPUT" 2>&1; then
    note "phase=bootstrap outcome=failed"
    exit 1
fi

chmod 600 "$S0" "$TRACE"
session_fingerprint=$(sha256sum "$S0" | cut -c1-12)
note "phase=bootstrap outcome=passed S0=$S0 session_fingerprint=$session_fingerprint"
