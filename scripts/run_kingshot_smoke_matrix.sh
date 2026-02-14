#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
MAX_LIBS=${2:-5}
REPORT_DIR="$ROOT_DIR/reports"
SUMMARY_FILE="$REPORT_DIR/kingshot_smoke_matrix_summary.txt"
ALL_PROFILE_SUMMARY="$REPORT_DIR/kingshot_all_import_profiles_summary.txt"

if [ ! -x "$ROOT_DIR/tiny_dbt" ]; then
    echo "tiny_dbt not built. Run: make" >&2
    exit 1
fi
if [ ! -f "$APK_PATH" ]; then
    echo "APK not found: $APK_PATH" >&2
    exit 1
fi

mkdir -p "$REPORT_DIR"

case "$MAX_LIBS" in
    ''|*[!0-9]*)
        echo "MAX_LIBS must be a positive integer" >&2
        exit 1
        ;;
esac
if [ "$MAX_LIBS" -le 0 ]; then
    echo "MAX_LIBS must be > 0" >&2
    exit 1
fi

if [ ! -f "$ALL_PROFILE_SUMMARY" ]; then
    "$ROOT_DIR/scripts/generate_kingshot_all_import_profiles.sh" "$APK_PATH" >/dev/null
fi

TMP_LIBS=$(mktemp /tmp/kingshot_smoke_matrix_libs.XXXXXX.txt)
TMP_OUT=$(mktemp /tmp/kingshot_smoke_matrix_out.XXXXXX.txt)
trap 'rm -f "$TMP_LIBS" "$TMP_OUT"' EXIT INT TERM

awk 'NF >= 3 && $1 ~ /^lib\/arm64-v8a\/.*\.so$/ {print $1, $3}' "$ALL_PROFILE_SUMMARY" \
    | sort -k2,2nr \
    | head -n "$MAX_LIBS" \
    | awk '{print $1}' > "$TMP_LIBS"

if [ ! -s "$TMP_LIBS" ]; then
    echo "No libraries found in $ALL_PROFILE_SUMMARY" >&2
    exit 1
fi

: > "$SUMMARY_FILE"
echo "# Kingshot smoke matrix summary" >> "$SUMMARY_FILE"
echo "# APK: $APK_PATH" >> "$SUMMARY_FILE"
echo "# Columns: status lib symbol trace_lines unsupported_lines log_file" >> "$SUMMARY_FILE"

ok_count=0
fail_count=0
run_count=0

while IFS= read -r LIB_ENTRY; do
    [ -z "$LIB_ENTRY" ] && continue
    run_count=$((run_count + 1))
    LIB_BASENAME=$(basename "$LIB_ENTRY")
    LIB_NAME=${LIB_BASENAME%.so}
    LOG_FILE="$REPORT_DIR/kingshot_smoke_${LIB_NAME}.log"

    if "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" > "$TMP_OUT" 2>&1; then
        status="ok"
        ok_count=$((ok_count + 1))
    else
        status="fail"
        fail_count=$((fail_count + 1))
    fi

    cp "$TMP_OUT" "$LOG_FILE"
    symbol=$(sed -n 's/^  symbol:[[:space:]]*//p' "$TMP_OUT" | head -n 1)
    trace_lines=$(sed -n 's/^  trace:.*(\([0-9][0-9]*\) lines).*/\1/p' "$TMP_OUT" | head -n 1)
    unsupported_lines=$(sed -n 's/^  unsupported:.*(\([0-9][0-9]*\) lines).*/\1/p' "$TMP_OUT" | head -n 1)

    [ -z "$symbol" ] && symbol="-"
    [ -z "$trace_lines" ] && trace_lines="-"
    [ -z "$unsupported_lines" ] && unsupported_lines="-"

    printf '%s %s %s %s %s %s\n' \
        "$status" "$LIB_ENTRY" "$symbol" "$trace_lines" "$unsupported_lines" "$LOG_FILE" >> "$SUMMARY_FILE"
done < "$TMP_LIBS"

echo "Kingshot smoke matrix completed:"
echo "  runs:    $run_count"
echo "  ok:      $ok_count"
echo "  fail:    $fail_count"
echo "  summary: $SUMMARY_FILE"
