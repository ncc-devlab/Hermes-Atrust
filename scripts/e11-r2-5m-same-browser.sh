#!/usr/bin/env bash
# E11 R2-B1: keep one browser alive and request a second CAS challenge at T0+5m.
set -uo pipefail

umask 077

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="${PROBE:-$REPO/target/debug/atrust-probe}"
RUN_DIR="${HERMES_E11_R2_5M_RUN_DIR:-$HOME/.hermes/e11-r2-5m}"
PROFILE="${HERMES_E11_R2_5M_PROFILE:-$RUN_DIR/browser-profile}"
S0="$RUN_DIR/S0.json"
S1="$RUN_DIR/S1.json"
S1_TMP="$S1.tmp"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
TARGET="${HERMES_E11_R2_TARGET:-202.117.112.71:8081}"
LOGIN_DOMAIN="${HERMES_LOGIN_DOMAIN:-cas42187}"
WEBDRIVER_PORT="${HERMES_E11_R2_5M_WEBDRIVER_PORT:-9518}"
CHROMEDRIVER="${CHROMEDRIVER:-$HOME/.local/bin/chromedriver}"
RENEWAL_AFTER="${HERMES_E11_R2_5M_RENEWAL_SECONDS:-300}"
FIRST_EXPIRY_CHECK_AGE="${HERMES_E11_R2_FIRST_EXPIRY_CHECK_AGE_SECONDS:-7200}"
EXPIRY_DEADLINE_AGE="${HERMES_E11_R2_EXPIRY_DEADLINE_AGE_SECONDS:-15300}"
EXPIRY_POLL="${HERMES_E11_R2_EXPIRY_POLL_SECONDS:-300}"
RUN_ID="$(date +%Y-%m-%d-%H%M%S)"
SUMMARY="$RUN_DIR/summary.log"
OUTPUT="$RUN_DIR/$RUN_ID-runner-output.log"
TRACE="$RUN_DIR/$RUN_ID-browser-trace.jsonl"
PROBE_LOG="$RUN_DIR/$RUN_ID-short-window.log"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }
fail() {
    note "run_id=$RUN_ID phase=R2-B1 outcome=failed reason=$1"
    exit 1
}
sleep_until_epoch() {
    local target=$1 now delay
    now=$(date +%s)
    delay=$((target - now))
    if ((delay > 0)); then
        sleep "$delay"
    fi
}
probe_log() {
    printf '%s/%s-%s.log' "$RUN_DIR" "$RUN_ID" "$1"
}
run_control_check() {
    local session=$1 label=$2 attempt_output log
    attempt_output="$RUN_DIR/$RUN_ID-$label-output.log"
    log=$(probe_log "$label")
    : >"$attempt_output"
    chmod 600 "$attempt_output"
    if HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$log" \
        session-check --session-file "$session" >"$attempt_output" 2>&1; then
        return 0
    fi
    if rg -qi '75500002|the session is invalid' "$attempt_output" "$log"; then
        return 10
    fi
    return 20
}
validate_full() {
    local session=$1 label=$2 src_port=$3 log
    if ! run_control_check "$session" "$label-control"; then
        return 1
    fi
    log=$(probe_log "$label-resource")
    if ! HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$log" \
        client-resource --session-file "$session" >>"$OUTPUT" 2>&1; then
        return 1
    fi
    log=$(probe_log "$label-get-ip")
    if ! HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$log" \
        get-ip --session-file "$session" --node "$NODE" --timeout-seconds 20 \
        >>"$OUTPUT" 2>&1; then
        return 1
    fi
    log=$(probe_log "$label-flow")
    if ! HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$log" \
        l3-session --session-file "$session" --node "$NODE" --target "$TARGET" \
        --probe tcp-syn --auth-only --src-port "$src_port" --connect-timeout-seconds 20 \
        >>"$OUTPUT" 2>&1; then
        return 1
    fi
}

if [[ -e "$RUN_DIR" ]]; then
    printf 'E11 R2-B1 run directory already exists: %s\n' "$RUN_DIR" >&2
    printf 'Archive or securely remove it before starting a new login day.\n' >&2
    exit 1
fi
mkdir -p "$RUN_DIR" "$PROFILE"
chmod 700 "$RUN_DIR" "$PROFILE"
touch "$SUMMARY" "$OUTPUT"
chmod 600 "$SUMMARY" "$OUTPUT"

[[ -x "$PROBE" ]] || fail "probe_missing"
if [[ ! -x "$CHROMEDRIVER" ]]; then
    CHROMEDRIVER=$(command -v chromedriver 2>/dev/null || true)
fi
[[ -n "$CHROMEDRIVER" && -x "$CHROMEDRIVER" ]] || fail "chromedriver_missing"
command -v rg >/dev/null 2>&1 || fail "ripgrep_missing"

driver_pid=""
experiment_pid=""
cleanup() {
    if [[ -n "$experiment_pid" ]]; then
        kill "$experiment_pid" 2>/dev/null || true
        wait "$experiment_pid" 2>/dev/null || true
    fi
    if [[ -n "$driver_pid" ]]; then
        kill "$driver_pid" 2>/dev/null || true
        wait "$driver_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

"$CHROMEDRIVER" --port="$WEBDRIVER_PORT" --log-path="$RUN_DIR/$RUN_ID-chromedriver.log" \
    >"$RUN_DIR/$RUN_ID-chromedriver-output.log" 2>&1 &
driver_pid=$!
sleep 1
kill -0 "$driver_pid" 2>/dev/null || fail "chromedriver_start_failed"

note "run_id=$RUN_ID phase=R2-B1 status=waiting_for_manual_CAS_MFA renewal_after_seconds=$RENEWAL_AFTER note=do_not_close_browser"
HERMES_LOG=info HERMES_CHROME_USER_DATA_DIR="$PROFILE" \
    "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$PROBE_LOG" \
    --browser-trace-file "$TRACE" e11-r2-short-window --login-domain "$LOGIN_DOMAIN" \
    --webdriver-url "http://127.0.0.1:$WEBDRIVER_PORT" --interaction-timeout-seconds 1800 \
    --renewal-after-seconds "$RENEWAL_AFTER" --unattended-timeout-seconds 300 \
    --s0-file "$S0" --s1-temp-file "$S1_TMP" >>"$OUTPUT" 2>&1 &
experiment_pid=$!

while [[ ! -f "$S0" ]]; do
    if ! kill -0 "$experiment_pid" 2>/dev/null; then
        wait "$experiment_pid"
        fail "bootstrap_or_S0_creation_failed"
    fi
    sleep 1
done
chmod 600 "$S0" "$TRACE"
s0_file_fingerprint=$(sha256sum "$S0" | cut -c1-12)
session_mtime=$(stat -c %Y "$S0")
note "run_id=$RUN_ID phase=R2-B1 checkpoint=S0_created outcome=passed S0_session_fingerprint=$s0_file_fingerprint"

if ! validate_full "$S0" "S0-baseline" 47010; then
    fail "S0_baseline_validation_failed"
fi
note "run_id=$RUN_ID phase=R2-B1 checkpoint=S0_baseline outcome=passed"

if wait "$experiment_pid"; then
    experiment_pid=""
else
    status=$?
    experiment_pid=""
    if rg -q 'probe.e11.r2_short_window.candidate_started' "$PROBE_LOG" \
        && rg -qi 'requires interaction|timed out waiting' "$OUTPUT" "$PROBE_LOG"; then
        note "run_id=$RUN_ID phase=R2-B1 outcome=interaction_required exit=$status"
        exit 2
    fi
    fail "short_window_probe_failed"
fi

[[ -f "$S1_TMP" ]] || fail "short_window_produced_no_candidate"
chmod 600 "$S1_TMP" "$TRACE"
if ! validate_full "$S1_TMP" "S1-immediate" 47011; then
    fail "S1_immediate_validation_failed"
fi
mv "$S1_TMP" "$S1"
chmod 600 "$S1"

if ! HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls \
    --log-file "$(probe_log S0-S1-compare)" session-compare --baseline "$S0" --candidate "$S1" \
    >>"$OUTPUT" 2>&1; then
    fail "session_comparison_failed"
fi
s1_file_fingerprint=$(sha256sum "$S1" | cut -c1-12)
note "run_id=$RUN_ID phase=R2-B1 checkpoint=S1_committed outcome=passed S1_session_fingerprint=$s1_file_fingerprint comparison_log=$(probe_log S0-S1-compare)"

check_index=0
while true; do
    now=$(date +%s)
    age=$((now - session_mtime))
    if ((check_index > 0 && age < FIRST_EXPIRY_CHECK_AGE)); then
        sleep_until_epoch $((session_mtime + FIRST_EXPIRY_CHECK_AGE))
        now=$(date +%s)
        age=$((now - session_mtime))
    fi
    if run_control_check "$S0" "S0-expiry-$check_index"; then
        note "run_id=$RUN_ID phase=R2-B1 checkpoint=S0_expiry status=still_valid session_age_seconds=$age"
    else
        status=$?
        if ((status == 10)); then
            note "run_id=$RUN_ID phase=R2-B1 checkpoint=S0_expiry outcome=session_invalid session_age_seconds=$age"
            if ! validate_full "$S1" "S1-decisive" 47012; then
                fail "S0_invalid_but_S1_validation_failed"
            fi
            current_s0_fingerprint=$(sha256sum "$S0" | cut -c1-12)
            [[ "$current_s0_fingerprint" == "$s0_file_fingerprint" ]] || fail "S0_file_changed"
            note "run_id=$RUN_ID phase=R2-B1 outcome=passed model=R2-same-browser-5m S0_invalid=true S1_valid=true S0_unchanged=true comparison_log=$(probe_log S0-S1-compare)"
            exit 0
        fi
        fail "S0_expiry_check_transport_failed"
    fi
    if ((age >= EXPIRY_DEADLINE_AGE)); then
        note "run_id=$RUN_ID phase=R2-B1 outcome=inconclusive reason=S0_still_valid_at_deadline session_age_seconds=$age"
        exit 3
    fi
    check_index=$((check_index + 1))
    sleep "$EXPIRY_POLL"
done
