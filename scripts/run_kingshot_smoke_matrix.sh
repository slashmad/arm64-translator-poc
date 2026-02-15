#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
MAX_LIBS=${2:-10}
SYMS_PER_LIB=${3:-2}
ATTEMPTS=${4:-2}
REPORT_DIR="$ROOT_DIR/reports"
SUMMARY_FILE="$REPORT_DIR/kingshot_smoke_matrix_summary.txt"
EXIT_REASON_SUMMARY_FILE="$REPORT_DIR/kingshot_smoke_matrix_exit_reason_summary.txt"
ALL_PROFILE_SUMMARY="$REPORT_DIR/kingshot_all_import_profiles_summary.txt"
SMOKE_MAX_RETRIES=${SMOKE_MAX_RETRIES:-}

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
case "$ATTEMPTS" in
    ''|*[!0-9]*)
        echo "ATTEMPTS must be a positive integer" >&2
        exit 1
        ;;
esac
case "$SYMS_PER_LIB" in
    ''|*[!0-9]*)
        echo "SYMS_PER_LIB must be a positive integer" >&2
        exit 1
        ;;
esac
if [ "$SYMS_PER_LIB" -le 0 ]; then
    echo "SYMS_PER_LIB must be > 0" >&2
    exit 1
fi
if [ "$ATTEMPTS" -le 0 ]; then
    echo "ATTEMPTS must be > 0" >&2
    exit 1
fi
if [ -n "$SMOKE_MAX_RETRIES" ]; then
    case "$SMOKE_MAX_RETRIES" in
        ''|*[!0-9]*)
            echo "SMOKE_MAX_RETRIES must be a positive integer when set" >&2
            exit 1
            ;;
    esac
    if [ "$SMOKE_MAX_RETRIES" -le 0 ]; then
        echo "SMOKE_MAX_RETRIES must be > 0 when set" >&2
        exit 1
    fi
fi

if [ ! -f "$ALL_PROFILE_SUMMARY" ]; then
    "$ROOT_DIR/scripts/generate_kingshot_all_import_profiles.sh" "$APK_PATH" >/dev/null
fi

TMP_LIBS=$(mktemp /tmp/kingshot_smoke_matrix_libs.XXXXXX.txt)
TMP_OUT=$(mktemp /tmp/kingshot_smoke_matrix_out.XXXXXX.txt)
TMP_LIB=$(mktemp /tmp/kingshot_smoke_matrix_lib.XXXXXX.so)
TMP_SYMS_ALL=$(mktemp /tmp/kingshot_smoke_matrix_syms_all.XXXXXX.txt)
TMP_SYMS_PICK=$(mktemp /tmp/kingshot_smoke_matrix_syms_pick.XXXXXX.txt)
trap 'rm -f "$TMP_LIBS" "$TMP_OUT" "$TMP_LIB" "$TMP_SYMS_ALL" "$TMP_SYMS_PICK"' EXIT INT TERM

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
echo "# Params: max_libs=$MAX_LIBS syms_per_lib=$SYMS_PER_LIB attempts=$ATTEMPTS smoke_max_retries=${SMOKE_MAX_RETRIES:-auto}" >> "$SUMMARY_FILE"
echo "# Columns: status lib symbol attempts tiny_rc exit_reason trace_lines unsupported_lines log_file" >> "$SUMMARY_FILE"

ok_count=0
fail_count=0
run_count=0

extract_symbols() {
    lib_entry=$1
    syms_per_lib=$2
    unzip -p "$APK_PATH" "$lib_entry" > "$TMP_LIB" || return 1
    if [ ! -s "$TMP_LIB" ]; then
        return 1
    fi
    readelf --wide -Ws "$TMP_LIB" \
        | awk '$4 == "FUNC" && $7 != "UND" && $3 != "0" {
            name = $8
            sub(/@.*/, "", name)
            if (name != "") {
                print name
            }
        }' \
        | sort -u > "$TMP_SYMS_ALL"
    if [ ! -s "$TMP_SYMS_ALL" ]; then
        return 1
    fi

    : > "$TMP_SYMS_PICK"
    if grep -qx "JNI_OnLoad" "$TMP_SYMS_ALL"; then
        echo "JNI_OnLoad" >> "$TMP_SYMS_PICK"
    fi
    awk '$0 != "JNI_OnLoad"' "$TMP_SYMS_ALL" >> "$TMP_SYMS_PICK"
    head -n "$syms_per_lib" "$TMP_SYMS_PICK" > "${TMP_SYMS_PICK}.head"
    mv "${TMP_SYMS_PICK}.head" "$TMP_SYMS_PICK"
    [ -s "$TMP_SYMS_PICK" ]
}

while IFS= read -r LIB_ENTRY; do
    [ -z "$LIB_ENTRY" ] && continue
    LIB_BASENAME=$(basename "$LIB_ENTRY")
    LIB_NAME=${LIB_BASENAME%.so}
    if ! extract_symbols "$LIB_ENTRY" "$SYMS_PER_LIB"; then
        printf 'skip %s - 0 1 - - - %s\n' "$LIB_ENTRY" "$REPORT_DIR/kingshot_smoke_${LIB_NAME}_extract.log" >> "$SUMMARY_FILE"
        fail_count=$((fail_count + 1))
        continue
    fi

    while IFS= read -r SYMBOL; do
        [ -z "$SYMBOL" ] && continue
        run_count=$((run_count + 1))
        SYMBOL_TAG=$(printf '%s' "$SYMBOL" | tr -c '[:alnum:]_-' '_')
        LOG_FILE="$REPORT_DIR/kingshot_smoke_${LIB_NAME}_${SYMBOL_TAG}.log"

        : > "$LOG_FILE"
        status="fail"
        tiny_rc=1
        attempts_used=0
        attempt=1
        while [ "$attempt" -le "$ATTEMPTS" ]; do
            attempts_used=$attempt
            set +e
            if [ -n "$SMOKE_MAX_RETRIES" ]; then
                "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" "$SMOKE_MAX_RETRIES" > "$TMP_OUT" 2>&1
                tiny_rc=$?
            else
                "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" > "$TMP_OUT" 2>&1
                tiny_rc=$?
            fi
            set -e
            {
                echo "=== attempt $attempt/$ATTEMPTS rc=$tiny_rc symbol=$SYMBOL ==="
                cat "$TMP_OUT"
            } >> "$LOG_FILE"
            if [ "$tiny_rc" -eq 0 ]; then
                status="ok"
                break
            fi
            attempt=$((attempt + 1))
        done
        if [ "$status" = "ok" ]; then
            ok_count=$((ok_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi

        symbol=$(sed -n 's/^  symbol:[[:space:]]*//p' "$TMP_OUT" | head -n 1)
        exit_reason=$(sed -n 's/^  exit_reason:[[:space:]]*//p' "$TMP_OUT" | head -n 1)
        trace_lines=$(sed -n 's/^  trace:.*(\([0-9][0-9]*\) lines).*/\1/p' "$TMP_OUT" | head -n 1)
        unsupported_lines=$(sed -n 's/^  unsupported:.*(\([0-9][0-9]*\) lines).*/\1/p' "$TMP_OUT" | head -n 1)

        [ -z "$symbol" ] && symbol="$SYMBOL"
        [ -z "$exit_reason" ] && exit_reason="-"
        [ -z "$trace_lines" ] && trace_lines="-"
        [ -z "$unsupported_lines" ] && unsupported_lines="-"

        printf '%s %s %s %s %s %s %s %s %s\n' \
            "$status" "$LIB_ENTRY" "$symbol" "$attempts_used" "$tiny_rc" "$exit_reason" "$trace_lines" "$unsupported_lines" "$LOG_FILE" >> "$SUMMARY_FILE"
    done < "$TMP_SYMS_PICK"
done < "$TMP_LIBS"

: > "$EXIT_REASON_SUMMARY_FILE"
echo "# Kingshot smoke matrix exit-reason summary" >> "$EXIT_REASON_SUMMARY_FILE"
echo "# Columns: count status exit_reason" >> "$EXIT_REASON_SUMMARY_FILE"
awk 'NF >= 9 && $1 !~ /^#/ { key=$1 FS $6; c[key]++; } END { for (k in c) { print c[k], k; } }' "$SUMMARY_FILE" \
    | sort -nr \
    | awk '{printf "%s %s %s\n", $1, $2, $3}' >> "$EXIT_REASON_SUMMARY_FILE"

echo "Kingshot smoke matrix completed:"
echo "  runs:    $run_count"
echo "  ok:      $ok_count"
echo "  fail:    $fail_count"
echo "  summary: $SUMMARY_FILE"
echo "  reasons: $EXIT_REASON_SUMMARY_FILE"
