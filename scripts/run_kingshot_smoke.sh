#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
LIB_ENTRY=${2:-lib/arm64-v8a/libmain.so}
SYMBOL=${3:-}
PROFILE_DIR="$ROOT_DIR/profiles"
REPORT_DIR="$ROOT_DIR/reports"

choose_symbol() {
    readelf --wide -Ws "$1" | awk '
        $4 == "FUNC" && $7 != "UND" && $3 != "0" {
            name = $8
            sub(/@.*/, "", name)
            if (name == "JNI_OnLoad") {
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
            if (name != "") {
                print name
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

mkdir -p "$PROFILE_DIR" "$REPORT_DIR"

LIB_BASENAME=$(basename "$LIB_ENTRY")
LIB_NAME=${LIB_BASENAME%.so}
CALLBACK_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_callbacks.txt"
STUB_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_stubs.txt"
TRACE_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_import_trace_smoke.txt"
UNSUPPORTED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_unsupported_smoke.txt"

if [ ! -f "$CALLBACK_FILE" ] || [ ! -f "$STUB_FILE" ]; then
    "$ROOT_DIR/scripts/generate_kingshot_import_profile.sh" "$APK_PATH" "$LIB_ENTRY" >/dev/null
fi

TMP_LIB=$(mktemp /tmp/kingshot_smoke_lib.XXXXXX.so)
trap 'rm -f "$TMP_LIB"' EXIT INT TERM

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
if [ -z "$SYMBOL" ]; then
    echo "Could not find runnable symbol in $LIB_ENTRY" >&2
    exit 1
fi

: > "$TRACE_FILE"
: > "$UNSUPPORTED_FILE"

set -- \
    --elf-file "$TMP_LIB" \
    --elf-symbol "$SYMBOL" \
    --elf-import-trace "$TRACE_FILE" \
    --log-unsupported "$UNSUPPORTED_FILE"

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

"$ROOT_DIR/tiny_dbt" "$@"

unsupported_count=$(grep -cve '^[[:space:]]*$' "$UNSUPPORTED_FILE" || true)
trace_count=$(grep -cve '^[[:space:]]*$' "$TRACE_FILE" || true)
echo "Kingshot smoke run completed:"
echo "  lib:         $LIB_ENTRY"
echo "  symbol:      $SYMBOL"
echo "  trace:       $TRACE_FILE ($trace_count lines)"
echo "  unsupported: $UNSUPPORTED_FILE ($unsupported_count lines)"
