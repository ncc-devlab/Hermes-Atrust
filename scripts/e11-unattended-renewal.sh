#!/usr/bin/env bash
# E11 R1: test authConfig renewal using an externally refreshed session.
set -uo pipefail

umask 077

REPO="${REPO:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROBE="${PROBE:-$REPO/target/debug/atrust-probe}"
RUN_DIR="${HERMES_E11_RUN_DIR:-$HOME/.hermes/e11}"
SESSION="${HERMES_SESSION_FILE:-$HOME/.hermes/xidian-session.json}"
GATEWAY="${HERMES_GATEWAY:-atrust.xidian.edu.cn}"
NODE="${HERMES_NODE:-61.150.43.94:441}"
MAX_INITIAL_AGE="${HERMES_E11_MAX_INITIAL_SESSION_AGE_SECONDS:-900}"
FIRST_RENEWAL="${HERMES_E11_FIRST_RENEWAL_SECONDS:-7200}"
FIRST_VALIDATION="${HERMES_E11_FIRST_VALIDATION_SECONDS:-14400}"
RENEWAL_INTERVAL="${HERMES_E11_RENEWAL_INTERVAL_SECONDS:-11700}"
REPEAT_RENEWALS="${HERMES_E11_REPEAT_RENEWALS:-4}"
SUMMARY="$RUN_DIR/summary.log"
RUN_ID="$(date +%Y-%m-%d-%H%M%S)"
LOG="$RUN_DIR/$RUN_ID-r1-auth-config.log"
OUTPUT="$RUN_DIR/$RUN_ID-runner-output.log"

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"
touch "$SUMMARY" "$LOG" "$OUTPUT"
chmod 600 "$SUMMARY" "$LOG" "$OUTPUT"

note() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$SUMMARY"; }

if [[ ! -x "$PROBE" ]]; then
  note "outcome=precondition_failed reason=probe_missing"
  exit 1
fi
if [[ ! -f "$SESSION" ]]; then
  note "outcome=precondition_failed reason=session_missing"
  exit 1
fi

session_fingerprint=$(sha256sum "$SESSION" | cut -c1-12)
session_mtime=$(stat -c %Y "$SESSION")
started=$(date +%s)
session_age=$((started - session_mtime))
if (( session_age < 0 || session_age > MAX_INITIAL_AGE )); then
  note "run_id=$RUN_ID outcome=precondition_failed reason=session_not_fresh session_age_seconds=$session_age max_initial_age_seconds=$MAX_INITIAL_AGE session_fingerprint=$session_fingerprint"
  exit 1
fi
total_seconds=$((FIRST_VALIDATION + RENEWAL_INTERVAL * REPEAT_RENEWALS))
note "run_id=$RUN_ID phase=R1-authConfig status=started session_age_seconds=$session_age first_renewal_seconds=$FIRST_RENEWAL first_validation_seconds=$FIRST_VALIDATION renewal_interval_seconds=$RENEWAL_INTERVAL repeat_renewals=$REPEAT_RENEWALS total_seconds=$total_seconds session_fingerprint=$session_fingerprint log=$LOG"

if HERMES_LOG=info "$PROBE" --host "$GATEWAY" --insecure-tls --log-file "$LOG" \
  session-renewal --session-file "$SESSION" --node "$NODE" \
  --first-renewal-after-seconds "$FIRST_RENEWAL" \
  --first-validation-after-seconds "$FIRST_VALIDATION" \
  --renewal-interval-seconds "$RENEWAL_INTERVAL" \
  --repeat-renewals "$REPEAT_RENEWALS" \
  --get-ip-timeout-seconds 20 >>"$OUTPUT" 2>&1; then
  ended=$(date +%s)
  note "run_id=$RUN_ID outcome=passed model=R1-authConfig elapsed_seconds=$((ended - started)) session_age_seconds=$((ended - session_mtime)) session_fingerprint=$session_fingerprint"
  exit 0
else
  status=$?
fi

ended=$(date +%s)
note "run_id=$RUN_ID outcome=failed model=R1-authConfig elapsed_seconds=$((ended - started)) session_age_seconds=$((ended - session_mtime)) exit=$status session_fingerprint=$session_fingerprint"
exit "$status"
