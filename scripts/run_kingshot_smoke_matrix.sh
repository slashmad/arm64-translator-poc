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
METRICS_FILE="$REPORT_DIR/kingshot_smoke_matrix_metrics.txt"
BLACKLIST_SUGGESTIONS_FILE="$REPORT_DIR/kingshot_smoke_blacklist_suggestions.txt"
ALL_PROFILE_SUMMARY="$REPORT_DIR/kingshot_all_import_profiles_summary.txt"
SMOKE_MAX_RETRIES=${SMOKE_MAX_RETRIES:-}
SMOKE_FAIL_ON_ERROR=${SMOKE_FAIL_ON_ERROR:-0}
SMOKE_TIMEOUT_SEC=${SMOKE_TIMEOUT_SEC:-25}
SMOKE_BLACKLIST_FILE=${SMOKE_BLACKLIST_FILE:-$ROOT_DIR/profiles/kingshot_smoke_blacklist.txt}
SMOKE_ALLOW_SYMBOL_INDEX=${SMOKE_ALLOW_SYMBOL_INDEX:-0}
PROFILE_MODE=${KSHOT_PROFILE_MODE:-relaxed}

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
case "$SMOKE_TIMEOUT_SEC" in
    ''|*[!0-9]*)
        echo "SMOKE_TIMEOUT_SEC must be a non-negative integer" >&2
        exit 1
        ;;
esac
case "$SMOKE_FAIL_ON_ERROR" in
    0|1)
        ;;
    *)
        echo "SMOKE_FAIL_ON_ERROR must be 0 or 1 when set" >&2
        exit 1
        ;;
esac
case "$SMOKE_ALLOW_SYMBOL_INDEX" in
    0|1)
        ;;
    *)
        echo "SMOKE_ALLOW_SYMBOL_INDEX must be 0 or 1 when set" >&2
        exit 1
        ;;
esac

SMOKE_TIMEOUT_BIN=
if [ "$SMOKE_TIMEOUT_SEC" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
    SMOKE_TIMEOUT_BIN=$(command -v timeout)
fi
if [ "$SMOKE_TIMEOUT_SEC" -gt 0 ] && [ -z "$SMOKE_TIMEOUT_BIN" ]; then
    echo "warning: 'timeout' command not found; SMOKE_TIMEOUT_SEC ignored" >&2
fi

if [ ! -f "$ALL_PROFILE_SUMMARY" ] || ! grep -q "^# Mode: $PROFILE_MODE$" "$ALL_PROFILE_SUMMARY"; then
    "$ROOT_DIR/scripts/generate_kingshot_all_import_profiles.sh" "$APK_PATH" "$PROFILE_MODE" >/dev/null
fi

TMP_LIBS=$(mktemp /tmp/kingshot_smoke_matrix_libs.XXXXXX.txt)
TMP_OUT=$(mktemp /tmp/kingshot_smoke_matrix_out.XXXXXX.txt)
TMP_LIB=$(mktemp /tmp/kingshot_smoke_matrix_lib.XXXXXX.so)
TMP_SYMS_ALL=$(mktemp /tmp/kingshot_smoke_matrix_syms_all.XXXXXX.txt)
TMP_SYMS_PICK=$(mktemp /tmp/kingshot_smoke_matrix_syms_pick.XXXXXX.txt)
TMP_SYMS_INDEX=$(mktemp /tmp/kingshot_smoke_matrix_syms_index.XXXXXX.txt)
TMP_BLACKLIST=$(mktemp /tmp/kingshot_smoke_matrix_blacklist.XXXXXX.txt)
trap 'rm -f "$TMP_LIBS" "$TMP_OUT" "$TMP_LIB" "$TMP_SYMS_ALL" "$TMP_SYMS_PICK" "$TMP_SYMS_INDEX" "$TMP_BLACKLIST"' EXIT INT TERM

: > "$TMP_BLACKLIST"
if [ -f "$SMOKE_BLACKLIST_FILE" ]; then
    awk '
        {
            line = $0;
            sub(/[[:space:]]*#.*$/, "", line);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line);
            if (line != "") {
                print line;
            }
        }
    ' "$SMOKE_BLACKLIST_FILE" | sort -u > "$TMP_BLACKLIST"
fi

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
echo "# Params: mode=$PROFILE_MODE max_libs=$MAX_LIBS syms_per_lib=$SYMS_PER_LIB attempts=$ATTEMPTS smoke_max_retries=${SMOKE_MAX_RETRIES:-auto} smoke_fail_on_error=$SMOKE_FAIL_ON_ERROR smoke_timeout_sec=$SMOKE_TIMEOUT_SEC smoke_blacklist_file=$SMOKE_BLACKLIST_FILE" >> "$SUMMARY_FILE"
echo "# Columns: status lib symbol attempts tiny_rc exit_reason trace_lines unsupported_lines log_file" >> "$SUMMARY_FILE"

: > "$METRICS_FILE"
echo "# Kingshot smoke matrix metrics" >> "$METRICS_FILE"
echo "# Columns: status lib symbol attempts callback_branches local_ret_branches import_value_branches import_total_branches callback_hitrate_pct trace_lines unsupported_lines" >> "$METRICS_FILE"

ok_count=0
fail_count=0
skip_count=0
run_count=0
attempts_total=0
retries_total=0
trace_total=0
unsupported_total=0
callback_branches_total=0
import_branch_total=0

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
            if (name != "" && name ~ /^[A-Za-z0-9_.$@]+$/) {
                print name
            }
        }' \
        | sort -u > "$TMP_SYMS_ALL"

    : > "$TMP_SYMS_PICK"
    if [ -s "$TMP_SYMS_ALL" ]; then
        if grep -qx "JNI_OnLoad" "$TMP_SYMS_ALL"; then
            echo "JNI_OnLoad" >> "$TMP_SYMS_PICK"
        fi
        awk '$0 != "JNI_OnLoad"' "$TMP_SYMS_ALL" >> "$TMP_SYMS_PICK"
        head -n "$syms_per_lib" "$TMP_SYMS_PICK" > "${TMP_SYMS_PICK}.head"
        mv "${TMP_SYMS_PICK}.head" "$TMP_SYMS_PICK"
        [ -s "$TMP_SYMS_PICK" ] && return 0
    fi

    if [ "$SMOKE_ALLOW_SYMBOL_INDEX" != "1" ]; then
        return 1
    fi

    readelf --wide -Ws "$TMP_LIB" \
        | awk '($4 == "FUNC") && ($5 == "GLOBAL" || $5 == "WEAK") && $7 != "UND" {
            size = $3 + 0
            value = $2
            if (size <= 0 || (size % 4) != 0) {
                next
            }
            if (value ~ /^0+$/) {
                next
            }
            idx = $1
            sub(/:$/, "", idx)
            if (idx ~ /^[0-9]+$/) {
                print "index:" idx
            }
        }' \
        | head -n "$syms_per_lib" > "$TMP_SYMS_INDEX"

    if [ ! -s "$TMP_SYMS_INDEX" ]; then
        return 1
    fi
    cp "$TMP_SYMS_INDEX" "$TMP_SYMS_PICK"
    return 0
}

is_blacklisted() {
    lib_entry=$1
    symbol=$2
    if [ ! -s "$TMP_BLACKLIST" ]; then
        return 1
    fi
    if grep -Fqx "$lib_entry" "$TMP_BLACKLIST"; then
        return 0
    fi
    if [ -n "$symbol" ] && grep -Fqx "$lib_entry:$symbol" "$TMP_BLACKLIST"; then
        return 0
    fi
    return 1
}

while IFS= read -r LIB_ENTRY; do
    [ -z "$LIB_ENTRY" ] && continue
    LIB_BASENAME=$(basename "$LIB_ENTRY")
    LIB_NAME=${LIB_BASENAME%.so}
    if is_blacklisted "$LIB_ENTRY" ""; then
        printf 'skip %s - 0 0 blacklist - - -\n' "$LIB_ENTRY" >> "$SUMMARY_FILE"
        skip_count=$((skip_count + 1))
        continue
    fi
    if ! extract_symbols "$LIB_ENTRY" "$SYMS_PER_LIB"; then
        printf 'skip %s - 0 1 - - - %s\n' "$LIB_ENTRY" "$REPORT_DIR/kingshot_smoke_${LIB_NAME}_extract.log" >> "$SUMMARY_FILE"
        skip_count=$((skip_count + 1))
        continue
    fi

    while IFS= read -r SYMBOL; do
        [ -z "$SYMBOL" ] && continue
        if is_blacklisted "$LIB_ENTRY" "$SYMBOL"; then
            printf 'skip %s %s 0 0 blacklist - - -\n' "$LIB_ENTRY" "$SYMBOL" >> "$SUMMARY_FILE"
            skip_count=$((skip_count + 1))
            continue
        fi
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
            if [ -n "$SMOKE_TIMEOUT_BIN" ]; then
                if [ -n "$SMOKE_MAX_RETRIES" ]; then
                    "$SMOKE_TIMEOUT_BIN" "$SMOKE_TIMEOUT_SEC" "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" "$SMOKE_MAX_RETRIES" > "$TMP_OUT" 2>&1
                    tiny_rc=$?
                else
                    "$SMOKE_TIMEOUT_BIN" "$SMOKE_TIMEOUT_SEC" "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" > "$TMP_OUT" 2>&1
                    tiny_rc=$?
                fi
            else
                if [ -n "$SMOKE_MAX_RETRIES" ]; then
                    "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" "$SMOKE_MAX_RETRIES" > "$TMP_OUT" 2>&1
                    tiny_rc=$?
                else
                    "$ROOT_DIR/scripts/run_kingshot_smoke.sh" "$APK_PATH" "$LIB_ENTRY" "$SYMBOL" > "$TMP_OUT" 2>&1
                    tiny_rc=$?
                fi
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
        symbol=$(sed -n 's/^  symbol:[[:space:]]*//p' "$TMP_OUT" | head -n 1)
        exit_reason=$(sed -n 's/^  exit_reason:[[:space:]]*//p' "$TMP_OUT" | head -n 1)
        trace_lines=$(sed -n 's/^  trace:.*(\([0-9][0-9]*\) lines).*/\1/p' "$TMP_OUT" | head -n 1)
        unsupported_lines=$(sed -n 's/^  unsupported:.*(\([0-9][0-9]*\) lines).*/\1/p' "$TMP_OUT" | head -n 1)
        callback_branches=$(sed -n 's/^  import-callback:.*branches=\([0-9][0-9]*\).*/\1/p' "$TMP_OUT" | awk '{s+=$1} END {print s+0}')
        local_ret_branches=$(sed -n 's/^  local-ret: branches=\([0-9][0-9]*\).*/\1/p' "$TMP_OUT" | awk '{s+=$1} END {print s+0}')
        import_value_branches=$(sed -n 's/^  import-value: branches=\([0-9][0-9]*\).*/\1/p' "$TMP_OUT" | awk '{s+=$1} END {print s+0}')

        [ -z "$symbol" ] && symbol="$SYMBOL"
        if [ -z "$exit_reason" ] && [ "$tiny_rc" -eq 124 ]; then
            exit_reason="timeout"
        fi
        [ -z "$exit_reason" ] && exit_reason="-"
        [ -z "$trace_lines" ] && trace_lines="-"
        [ -z "$unsupported_lines" ] && unsupported_lines="-"
        import_total_branches=$((callback_branches + local_ret_branches + import_value_branches))
        if [ "$import_total_branches" -gt 0 ]; then
            callback_hitrate_pct=$(awk -v cb="$callback_branches" -v tot="$import_total_branches" 'BEGIN { printf "%.2f", (100.0*cb)/tot }')
        else
            callback_hitrate_pct="0.00"
        fi

        if [ "$status" = "fail" ] && [ "${symbol#index:}" != "$symbol" ]; then
            case "$exit_reason" in
                bad_code_size|no_ret|symbol_index_unrunnable|symbol_size_zero)
                    status="skip"
                    ;;
            esac
        fi
        if [ "$status" = "ok" ]; then
            ok_count=$((ok_count + 1))
        elif [ "$status" = "skip" ]; then
            skip_count=$((skip_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi

        attempts_total=$((attempts_total + attempts_used))
        retries_total=$((retries_total + attempts_used - 1))
        if [ "$trace_lines" != "-" ]; then
            trace_total=$((trace_total + trace_lines))
        fi
        if [ "$unsupported_lines" != "-" ]; then
            unsupported_total=$((unsupported_total + unsupported_lines))
        fi
        callback_branches_total=$((callback_branches_total + callback_branches))
        import_branch_total=$((import_branch_total + import_total_branches))

        printf '%s %s %s %s %s %s %s %s %s %s %s\n' \
            "$status" "$LIB_ENTRY" "$symbol" "$attempts_used" "$callback_branches" "$local_ret_branches" \
            "$import_value_branches" "$import_total_branches" "$callback_hitrate_pct" "$trace_lines" "$unsupported_lines" >> "$METRICS_FILE"

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

if [ "$run_count" -gt 0 ]; then
    avg_attempts=$(awk -v total="$attempts_total" -v runs="$run_count" 'BEGIN { printf "%.2f", total/runs }')
    avg_trace=$(awk -v total="$trace_total" -v runs="$run_count" 'BEGIN { printf "%.2f", total/runs }')
    avg_unsupported=$(awk -v total="$unsupported_total" -v runs="$run_count" 'BEGIN { printf "%.2f", total/runs }')
else
    avg_attempts="0.00"
    avg_trace="0.00"
    avg_unsupported="0.00"
fi
if [ "$import_branch_total" -gt 0 ]; then
    callback_hitrate_overall=$(awk -v cb="$callback_branches_total" -v tot="$import_branch_total" 'BEGIN { printf "%.2f", (100.0*cb)/tot }')
else
    callback_hitrate_overall="0.00"
fi
{
    echo "# Totals"
    echo "runs=$run_count"
    echo "ok=$ok_count"
    echo "fail=$fail_count"
    echo "skip=$skip_count"
    echo "attempts_total=$attempts_total"
    echo "retries_total=$retries_total"
    echo "avg_attempts_per_run=$avg_attempts"
    echo "avg_trace_lines_per_run=$avg_trace"
    echo "avg_unsupported_lines_per_run=$avg_unsupported"
    echo "import_callback_branches_total=$callback_branches_total"
    echo "import_branches_total=$import_branch_total"
    echo "import_callback_hitrate_pct=$callback_hitrate_overall"
} >> "$METRICS_FILE"

: > "$BLACKLIST_SUGGESTIONS_FILE"
{
    echo "# Suggested smoke blacklist entries (auto-generated)"
    echo "# Format: lib/arm64-v8a/libfoo.so[:symbol]"
    awk 'NF >= 9 && $1 == "fail" && $2 ~ /^lib\/arm64-v8a\/.*\.so$/ {
        printf "%s:%s # exit_reason=%s rc=%s\n", $2, $3, $6, $5;
    }' "$SUMMARY_FILE" | sort -u
} >> "$BLACKLIST_SUGGESTIONS_FILE"

echo "Kingshot smoke matrix completed:"
echo "  runs:    $run_count"
echo "  ok:      $ok_count"
echo "  fail:    $fail_count"
echo "  skip:    $skip_count"
echo "  summary: $SUMMARY_FILE"
echo "  reasons: $EXIT_REASON_SUMMARY_FILE"
echo "  metrics: $METRICS_FILE"
echo "  suggest: $BLACKLIST_SUGGESTIONS_FILE"

if [ "$fail_count" -gt 0 ] && [ "$SMOKE_FAIL_ON_ERROR" -eq 1 ]; then
    echo "Smoke matrix failed: $fail_count runs failed and SMOKE_FAIL_ON_ERROR=1" >&2
    exit 1
fi
