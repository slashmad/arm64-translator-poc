#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
PROFILE_MODE=${KSHOT_PROFILE_MODE:-relaxed}
MAX_RETRIES=${E2E_MAX_RETRIES:-}
REPORT_DIR="$ROOT_DIR/reports"
REPORT_FILE="$REPORT_DIR/kingshot_e2e_batch_report.txt"

if [ ! -x "$ROOT_DIR/tiny_dbt" ]; then
    echo "tiny_dbt not built. Run: make" >&2
    exit 1
fi
if [ ! -f "$APK_PATH" ]; then
    echo "APK not found: $APK_PATH" >&2
    exit 1
fi
mkdir -p "$REPORT_DIR"

: > "$REPORT_FILE"
{
    echo "# Kingshot E2E batch report"
    echo "# APK: $APK_PATH"
    echo "# Mode: $PROFILE_MODE"
    echo "# Columns: status lib symbol tiny_rc exit_reason trace_lines unsupported_lines log_file"
} >> "$REPORT_FILE"

cases='lib/arm64-v8a/libFirebaseCppApp-12_10_0.so|JNI_OnLoad
lib/arm64-v8a/libNetHTProtect.so|JNI_OnLoad
lib/arm64-v8a/libcrashlytics-common.so|CrashpadHandlerMain
lib/arm64-v8a/libcrashlytics.so|JNI_OnLoad
lib/arm64-v8a/libaudio-convert.so|ACELP_4t64_fx'

run_count=0
ok_count=0
fail_count=0

old_ifs=$IFS
IFS='
'
for row in $cases; do
    [ -z "$row" ] && continue
    IFS='|'
    set -- $row
    IFS=$old_ifs
    LIB_ENTRY=$1
    SYMBOL=$2

    run_count=$((run_count + 1))
    tag=$(printf '%s_%s' "$(basename "$LIB_ENTRY" .so)" "$SYMBOL" | tr -c '[:alnum:]_-' '_')
    LOG_FILE="$REPORT_DIR/kingshot_e2e_${tag}.log"

    set +e
    if [ -n "$MAX_RETRIES" ]; then
        KSHOT_PROFILE_MODE="$PROFILE_MODE" "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" "$MAX_RETRIES" > "$LOG_FILE" 2>&1
        tiny_rc=$?
    else
        KSHOT_PROFILE_MODE="$PROFILE_MODE" "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" > "$LOG_FILE" 2>&1
        tiny_rc=$?
    fi
    set -e

    status="ok"
    if [ "$tiny_rc" -ne 0 ]; then
        status="fail"
    fi

    exit_reason=$(sed -n 's/^  exit_reason:[[:space:]]*//p' "$LOG_FILE" | tail -n 1)
    trace_lines=$(sed -n 's/^  trace:.*(\([0-9][0-9]*\) lines).*/\1/p' "$LOG_FILE" | tail -n 1)
    unsupported_lines=$(sed -n 's/^  unsupported:.*(\([0-9][0-9]*\) lines).*/\1/p' "$LOG_FILE" | tail -n 1)
    [ -z "$exit_reason" ] && exit_reason="-"
    [ -z "$trace_lines" ] && trace_lines="-"
    [ -z "$unsupported_lines" ] && unsupported_lines="-"

    if [ "$status" = "ok" ]; then
        ok_count=$((ok_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi

    printf '%s %s %s %s %s %s %s %s\n' \
        "$status" "$LIB_ENTRY" "$SYMBOL" "$tiny_rc" "$exit_reason" "$trace_lines" "$unsupported_lines" "$LOG_FILE" >> "$REPORT_FILE"

done
IFS=$old_ifs

{
    echo "# Summary"
    echo "runs=$run_count"
    echo "ok=$ok_count"
    echo "fail=$fail_count"

    echo "# Blockers"
    if [ "$fail_count" -gt 0 ]; then
        awk 'NF >= 8 && ($1 == "ok" || $1 == "fail") && $1 == "fail" {printf "- fail %s %s (rc=%s exit_reason=%s)\n", $2, $3, $4, $5}' "$REPORT_FILE"
    else
        echo "- no hard fail blockers in selected e2e batch"
    fi

    if awk 'NF >= 8 && ($1 == "ok" || $1 == "fail") && $7 != "-" && $7 != "0" {found=1} END{exit !found}' "$REPORT_FILE"; then
        awk 'NF >= 8 && ($1 == "ok" || $1 == "fail") && $7 != "-" && $7 != "0" {printf "- unsupported-opcode traces present for %s %s: %s lines\n", $2, $3, $7}' "$REPORT_FILE"
    else
        echo "- no unsupported-opcode blockers observed"
    fi

    echo "- known operational blocker outside this batch: non-returning entrypoints such as libcrashlytics-trampoline.so:_start (blacklisted for smoke matrix)."
} >> "$REPORT_FILE"

echo "Kingshot e2e batch completed:"
echo "  runs:    $run_count"
echo "  ok:      $ok_count"
echo "  fail:    $fail_count"
echo "  report:  $REPORT_FILE"
