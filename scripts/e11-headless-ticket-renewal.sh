#!/usr/bin/env bash
# E11 headless: ticketExchange(S0) -> sessionIdExchange(empty jar) at S0 age 5m.
set -uo pipefail

umask 077

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="${PROBE:-$REPO/target/debug/atrust-probe}"
SOURCE_SESSION="${HERMES_SESSION_FILE:-$HOME/.hermes/xidian-session.json}"
RUN_DIR="${HERMES_E11_HEADLESS_RUN_DIR:-$HOME/.hermes/e11-headless-ticket}"
S0="$RUN_DIR/S0.json"
S1="$RUN_DIR/S1.json"
S1_TMP="$S1.tmp"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
TARGET="${HERMES_E11_R2_TARGET:-202.117.112.71:8081}"
MAX_INITIAL_AGE="${HERMES_E11_HEADLESS_MAX_INITIAL_AGE_SECONDS:-900}"
EXCHANGE_AGE="${HERMES_E11_HEADLESS_EXCHANGE_AGE_SECONDS:-300}"
FIRST_EXPIRY_CHECK_AGE="${HERMES_E11_R2_FIRST_EXPIRY_CHECK_AGE_SECONDS:-7200}"
EXPIRY_DEADLINE_AGE="${HERMES_E11_R2_EXPIRY_DEADLINE_AGE_SECONDS:-15300}"
EXPIRY_POLL="${HERMES_E11_R2_EXPIRY_POLL_SECONDS:-300}"
RUN_ID="$(date +%Y-%m-%d-%H%M%S)"
SUMMARY="$RUN_DIR/summary.log"
OUTPUT="$RUN_DIR/$RUN_ID-runner-output.log"
EXCHANGE_LOG="$RUN_DIR/$RUN_ID-headless-exchange.log"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }
fail() {
    note "run_id=$RUN_ID phase=E11-headless outcome=failed reason=$1"
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
    printf 'E11 headless run directory already exists: %s\n' "$RUN_DIR" >&2
    printf 'Archive or securely remove it before starting a new login day.\n' >&2
    exit 1
fi
[[ -x "$PROBE" ]] || { printf 'atrust-probe is missing\n' >&2; exit 1; }
[[ -f "$SOURCE_SESSION" ]] || { printf 'fresh source session is missing\n' >&2; exit 1; }
command -v rg >/dev/null 2>&1 || { printf 'ripgrep is missing\n' >&2; exit 1; }

source_mtime=$(stat -c %Y "$SOURCE_SESSION")
now=$(date +%s)
source_age=$((now - source_mtime))
if ((source_age < 0 || source_age > MAX_INITIAL_AGE)); then
    printf 'source session is not fresh: age=%ss max=%ss\n' "$source_age" "$MAX_INITIAL_AGE" >&2
    exit 1
fi

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"
touch "$SUMMARY" "$OUTPUT"
chmod 600 "$SUMMARY" "$OUTPUT"
cp --preserve=timestamps "$SOURCE_SESSION" "$S0"
chmod 600 "$S0"

s0_file_fingerprint=$(sha256sum "$S0" | cut -c1-12)
session_mtime=$(stat -c %Y "$S0")
note "run_id=$RUN_ID phase=E11-headless status=started session_age_seconds=$source_age exchange_at_session_age_seconds=$EXCHANGE_AGE S0_session_fingerprint=$s0_file_fingerprint note=no_browser_no_webdriver"

if ! validate_full "$S0" "S0-baseline" 47020; then
    fail "S0_baseline_validation_failed"
fi
note "run_id=$RUN_ID phase=E11-headless checkpoint=S0_baseline outcome=passed"

if ! HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$EXCHANGE_LOG" \
    e11-headless-ticket-exchange --session-file "$S0" --s1-temp-file "$S1_TMP" \
    --exchange-at-session-age-seconds "$EXCHANGE_AGE" \
    --max-initial-session-age-seconds "$MAX_INITIAL_AGE" >>"$OUTPUT" 2>&1; then
    if rg -q 'probe.e11.headless_ticket.captured' "$EXCHANGE_LOG"; then
        note "run_id=$RUN_ID phase=E11-headless outcome=exchange_rejected stage=sessionIdExchange"
        exit 2
    fi
    fail "ticketExchange_failed"
fi

[[ -f "$S1_TMP" ]] || fail "headless_exchange_produced_no_candidate"
chmod 600 "$S1_TMP"
if ! validate_full "$S1_TMP" "S1-immediate" 47021; then
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
note "run_id=$RUN_ID phase=E11-headless checkpoint=S1_committed outcome=passed S1_session_fingerprint=$s1_file_fingerprint comparison_log=$(probe_log S0-S1-compare)"

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
        note "run_id=$RUN_ID phase=E11-headless checkpoint=S0_expiry status=still_valid session_age_seconds=$age"
    else
        status=$?
        if ((status == 10)); then
            note "run_id=$RUN_ID phase=E11-headless checkpoint=S0_expiry outcome=session_invalid session_age_seconds=$age"
            if ! validate_full "$S1" "S1-decisive" 47022; then
                fail "S0_invalid_but_S1_validation_failed"
            fi
            current_s0_fingerprint=$(sha256sum "$S0" | cut -c1-12)
            [[ "$current_s0_fingerprint" == "$s0_file_fingerprint" ]] || fail "S0_file_changed"
            note "run_id=$RUN_ID phase=E11-headless outcome=passed model=ticketExchange-sessionIdExchange S0_invalid=true S1_valid=true S0_unchanged=true comparison_log=$(probe_log S0-S1-compare)"
            exit 0
        fi
        fail "S0_expiry_check_transport_failed"
    fi
    if ((age >= EXPIRY_DEADLINE_AGE)); then
        note "run_id=$RUN_ID phase=E11-headless outcome=inconclusive reason=S0_still_valid_at_deadline session_age_seconds=$age"
        exit 3
    fi
    check_index=$((check_index + 1))
    sleep "$EXPIRY_POLL"
done
