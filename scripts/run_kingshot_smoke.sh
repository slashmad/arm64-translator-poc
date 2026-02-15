#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
LIB_ENTRY=${2:-lib/arm64-v8a/libmain.so}
SYMBOL=${3:-}
MAX_RETRIES=${4:-}
PROFILE_DIR="$ROOT_DIR/profiles"
REPORT_DIR="$ROOT_DIR/reports"
DEBUG_EXIT=${TINY_DBT_SMOKE_DEBUG_EXIT:-1}
PROFILE_MODE=${KSHOT_PROFILE_MODE:-relaxed}
ALLOW_SYMBOL_INDEX=${SMOKE_ALLOW_SYMBOL_INDEX:-0}

choose_symbol() {
    readelf --wide -Ws "$1" | awk '
        $4 == "FUNC" && $7 != "UND" && $3 != "0" {
            name = $8
            sub(/@.*/, "", name)
            if (name == "JNI_OnLoad" && name ~ /^[A-Za-z0-9_.$@]+$/) {
                print name
                exit
            }
        }'
}

choose_fallback_symbol() {
    readelf --wide -Ws "$1" | awk '
        $4 == "FUNC" && $7 != "UND" && $3 != "0" {
            name = $8
            sub(/@.*/, "", name)
            if (name != "" && name ~ /^[A-Za-z0-9_.$@]+$/) {
                print name
                exit
            }
        }'
}

choose_fallback_symbol_index() {
    readelf --wide -Ws "$1" | awk '
        $4 == "FUNC" && $7 != "UND" && $3 != "0" {
            idx = $1
            sub(/:$/, "", idx)
            if (idx ~ /^[0-9]+$/) {
                print idx
                exit
            }
        }'
}

if [ ! -x "$ROOT_DIR/tiny_dbt" ]; then
    echo "tiny_dbt not built. Run: make" >&2
    exit 1
fi
if [ ! -f "$APK_PATH" ]; then
    echo "APK not found: $APK_PATH" >&2
    exit 1
fi
if [ -n "$MAX_RETRIES" ]; then
    case "$MAX_RETRIES" in
        ''|*[!0-9]*)
            echo "MAX_RETRIES must be a positive integer when provided" >&2
            exit 1
            ;;
    esac
    if [ "$MAX_RETRIES" -le 0 ]; then
        echo "MAX_RETRIES must be > 0 when provided" >&2
        exit 1
    fi
fi
case "$ALLOW_SYMBOL_INDEX" in
    0|1)
        ;;
    *)
        echo "SMOKE_ALLOW_SYMBOL_INDEX must be 0 or 1 when set" >&2
        exit 1
        ;;
esac

mkdir -p "$PROFILE_DIR" "$REPORT_DIR"

LIB_BASENAME=$(basename "$LIB_ENTRY")
LIB_NAME=${LIB_BASENAME%.so}
CALLBACK_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_callbacks.txt"
STUB_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_stubs.txt"
TRACE_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_import_trace_smoke.txt"
UNSUPPORTED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_unsupported_smoke.txt"

if [ ! -f "$CALLBACK_FILE" ] || [ ! -f "$STUB_FILE" ]; then
    "$ROOT_DIR/scripts/generate_kingshot_import_profile.sh" "$APK_PATH" "$LIB_ENTRY" "$PROFILE_MODE" >/dev/null
fi

TMP_LIB=$(mktemp /tmp/kingshot_smoke_lib.XXXXXX.so)
TMP_OUT=$(mktemp /tmp/kingshot_smoke_out.XXXXXX.txt)
trap 'rm -f "$TMP_LIB" "$TMP_OUT"' EXIT INT TERM

unzip -p "$APK_PATH" "$LIB_ENTRY" > "$TMP_LIB"
if [ ! -s "$TMP_LIB" ]; then
    echo "Failed to extract $LIB_ENTRY from $APK_PATH" >&2
    exit 1
fi

if [ -z "$SYMBOL" ]; then
    SYMBOL=$(choose_symbol "$TMP_LIB")
fi
if [ -z "$SYMBOL" ]; then
    SYMBOL=$(choose_fallback_symbol "$TMP_LIB")
fi

SYMBOL_INDEX=""
if [ -n "$SYMBOL" ] && [ "${SYMBOL#index:}" != "$SYMBOL" ]; then
    SYMBOL_INDEX=${SYMBOL#index:}
    SYMBOL=""
fi
if [ -n "$SYMBOL_INDEX" ]; then
    case "$SYMBOL_INDEX" in
        ''|*[!0-9]*)
            echo "Invalid symbol index token: index:$SYMBOL_INDEX" >&2
            exit 1
            ;;
    esac
fi
if [ -z "$SYMBOL" ] && [ -z "$SYMBOL_INDEX" ]; then
    if [ "$ALLOW_SYMBOL_INDEX" = "1" ]; then
        SYMBOL_INDEX=$(choose_fallback_symbol_index "$TMP_LIB")
    fi
fi
if [ -z "$SYMBOL" ] && [ -z "$SYMBOL_INDEX" ]; then
    echo "Could not find runnable symbol or symbol index in $LIB_ENTRY" >&2
    exit 1
fi

: > "$TRACE_FILE"
: > "$UNSUPPORTED_FILE"

set -- \
    --elf-file "$TMP_LIB"
if [ -n "$SYMBOL_INDEX" ]; then
    set -- "$@" --elf-symbol-index "$SYMBOL_INDEX"
else
    set -- "$@" --elf-symbol "$SYMBOL"
fi
set -- "$@" \
    --elf-import-trace "$TRACE_FILE" \
    --log-unsupported "$UNSUPPORTED_FILE"
if [ "$DEBUG_EXIT" != "0" ]; then
    set -- "$@" --debug-exit
fi
if [ -n "$MAX_RETRIES" ]; then
    set -- "$@" --max-retries "$MAX_RETRIES"
fi

if [ -f "$CALLBACK_FILE" ]; then
    while IFS= read -r spec; do
        [ -z "$spec" ] && continue
        case "$spec" in
            \#*) continue ;;
        esac
        set -- "$@" --elf-import-callback "$spec"
    done < "$CALLBACK_FILE"
fi
if [ -f "$STUB_FILE" ]; then
    while IFS= read -r spec; do
        [ -z "$spec" ] && continue
        case "$spec" in
            \#*) continue ;;
        esac
        set -- "$@" --elf-import-stub "$spec"
    done < "$STUB_FILE"
fi

set +e
"$ROOT_DIR/tiny_dbt" "$@" > "$TMP_OUT" 2>&1
tiny_rc=$?
set -e
cat "$TMP_OUT"

unsupported_count=$(grep -cve '^[[:space:]]*$' "$UNSUPPORTED_FILE" || true)
trace_count=$(grep -cve '^[[:space:]]*$' "$TRACE_FILE" || true)
exit_reason=$(sed -n 's/^debug:.*exit_reason=\([0-9][0-9]*\).*/\1/p' "$TMP_OUT" | tail -n 1)
[ -z "$exit_reason" ] && exit_reason="-"
if [ "$tiny_rc" -eq 0 ]; then
    status="ok"
else
    status="fail"
fi
echo "Kingshot smoke run completed:"
echo "  status:      $status"
echo "  lib:         $LIB_ENTRY"
if [ -n "$SYMBOL_INDEX" ]; then
    echo "  symbol:      index:$SYMBOL_INDEX"
else
    echo "  symbol:      $SYMBOL"
fi
echo "  mode:        $PROFILE_MODE"
echo "  exit_reason: $exit_reason"
echo "  trace:       $TRACE_FILE ($trace_count lines)"
echo "  unsupported: $UNSUPPORTED_FILE ($unsupported_count lines)"
exit "$tiny_rc"
