#!/usr/bin/env bash
# Resume the decisive S0-expired/S1-valid check after an interrupted E11 run.
set -uo pipefail

umask 077

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="${PROBE:-$REPO/target/debug/atrust-probe}"
RUN_DIR="${HERMES_E11_HEADLESS_RUN_DIR:-$HOME/.hermes/e11-headless-ticket}"
S0="$RUN_DIR/S0.json"
S1="$RUN_DIR/S1.json"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
TARGET="${HERMES_E11_R2_TARGET:-202.117.112.71:8081}"
POLL_SECONDS="${HERMES_E11_RESUME_POLL_SECONDS:-60}"
DEADLINE_AGE="${HERMES_E11_R2_EXPIRY_DEADLINE_AGE_SECONDS:-15300}"
RUN_ID="$(date +%Y-%m-%d-%H%M%S)-resume"
SUMMARY="$RUN_DIR/summary.log"
OUTPUT="$RUN_DIR/$RUN_ID-output.log"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }
fail() {
    note "run_id=$RUN_ID phase=E11-headless-resume outcome=failed reason=$1"
    exit 1
}
probe_log() {
    printf '%s/%s-%s.log' "$RUN_DIR" "$RUN_ID" "$1"
}
run_control_check() {
    local session=$1 label=$2 attempt attempt_output log
    for attempt in 1 2 3; do
        attempt_output="$RUN_DIR/$RUN_ID-$label-attempt-$attempt-output.log"
        log=$(probe_log "$label-attempt-$attempt")
        : >"$attempt_output"
        chmod 600 "$attempt_output"
        if HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$log" \
            session-check --session-file "$session" >"$attempt_output" 2>&1; then
            return 0
        fi
        if rg -qi '75500002|the session is invalid' "$attempt_output" "$log"; then
            return 10
        fi
        if ((attempt < 3)); then
            sleep 30
        fi
    done
    return 20
}
validate_full() {
    local session=$1 label=$2 log
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
        --probe tcp-syn --auth-only --src-port 47023 --connect-timeout-seconds 20 \
        >>"$OUTPUT" 2>&1; then
        return 1
    fi
}

[[ -x "$PROBE" ]] || fail "probe_missing"
[[ -f "$S0" ]] || fail "S0_missing"
[[ -f "$S1" ]] || fail "S1_missing"
command -v rg >/dev/null 2>&1 || fail "ripgrep_missing"
touch "$SUMMARY" "$OUTPUT"
chmod 600 "$SUMMARY" "$OUTPUT"

s0_fingerprint=$(sha256sum "$S0" | cut -c1-12)
s1_fingerprint=$(sha256sum "$S1" | cut -c1-12)
s0_mtime=$(stat -c %Y "$S0")
s1_mtime=$(stat -c %Y "$S1")
now=$(date +%s)
note "run_id=$RUN_ID phase=E11-headless-resume status=started S0_age_seconds=$((now - s0_mtime)) S1_age_seconds=$((now - s1_mtime)) poll_seconds=$POLL_SECONDS S0_session_fingerprint=$s0_fingerprint S1_session_fingerprint=$s1_fingerprint"

if run_control_check "$S1" "S1-resume-baseline"; then
    note "run_id=$RUN_ID phase=E11-headless-resume checkpoint=S1_resume_baseline outcome=passed"
else
    s1_status=$?
    if ((s1_status == 10)); then
        if run_control_check "$S0" "S0-resume-baseline"; then
            fail "S1_expired_before_S0"
        else
            s0_status=$?
            if ((s0_status == 10)); then
                note "run_id=$RUN_ID phase=E11-headless-resume outcome=failed_same_expiry S0_invalid=true S1_invalid=true"
                exit 2
            fi
            fail "S0_check_transport_failed_after_S1_expiry"
        fi
    fi
    fail "S1_resume_check_transport_failed"
fi

check_index=0
while true; do
    now=$(date +%s)
    s0_age=$((now - s0_mtime))
    s1_age=$((now - s1_mtime))
    if run_control_check "$S0" "S0-resume-$check_index"; then
        note "run_id=$RUN_ID phase=E11-headless-resume checkpoint=S0 status=still_valid check=$check_index S0_age_seconds=$s0_age S1_age_seconds=$s1_age"
    else
        status=$?
        if ((status == 10)); then
            note "run_id=$RUN_ID phase=E11-headless-resume checkpoint=S0 outcome=session_invalid check=$check_index S0_age_seconds=$s0_age S1_age_seconds=$s1_age"
            if ! validate_full "$S1" "S1-decisive-resume"; then
                note "run_id=$RUN_ID phase=E11-headless-resume outcome=failed_same_expiry S0_invalid=true S1_valid=false"
                exit 2
            fi
            [[ "$(sha256sum "$S0" | cut -c1-12)" == "$s0_fingerprint" ]] || fail "S0_file_changed"
            [[ "$(sha256sum "$S1" | cut -c1-12)" == "$s1_fingerprint" ]] || fail "S1_file_changed"
            note "run_id=$RUN_ID phase=E11-headless-resume outcome=passed model=ticketExchange-sessionIdExchange S0_invalid=true S1_valid=true files_unchanged=true"
            exit 0
        fi
        fail "S0_check_transport_failed"
    fi
    if ((s0_age >= DEADLINE_AGE)); then
        note "run_id=$RUN_ID phase=E11-headless-resume outcome=inconclusive reason=S0_still_valid_at_deadline S0_age_seconds=$s0_age"
        exit 3
    fi
    check_index=$((check_index + 1))
    sleep "$POLL_SECONDS"
done
