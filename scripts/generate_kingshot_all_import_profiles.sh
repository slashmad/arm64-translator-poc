#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
PROFILE_DIR="$ROOT_DIR/profiles"
REPORT_DIR="$ROOT_DIR/reports"
SUMMARY_FILE="$REPORT_DIR/kingshot_all_import_profiles_summary.txt"
UNMAPPED_ALL_FILE="$REPORT_DIR/kingshot_all_unmapped_imports.txt"

count_nonempty() {
    if [ ! -f "$1" ]; then
        echo 0
        return
    fi
    grep -cve '^[[:space:]]*$' "$1" || true
}

count_unmapped() {
    if [ ! -f "$1" ]; then
        echo 0
        return
    fi
    if grep -q '^# all imports mapped$' "$1"; then
        echo 0
        return
    fi
    grep -cve '^[[:space:]]*$' "$1" || true
}

if [ ! -f "$APK_PATH" ]; then
    echo "APK not found: $APK_PATH" >&2
    exit 1
fi

mkdir -p "$PROFILE_DIR" "$REPORT_DIR"

TMP_LIB_LIST=$(mktemp /tmp/kingshot_lib_list.XXXXXX.txt)
trap 'rm -f "$TMP_LIB_LIST"' EXIT INT TERM

unzip -Z1 "$APK_PATH" | awk '/^lib\/arm64-v8a\/.*\.so$/ {print}' | sort -u > "$TMP_LIB_LIST"
if [ ! -s "$TMP_LIB_LIST" ]; then
    echo "No arm64 shared libraries found in APK: $APK_PATH" >&2
    exit 1
fi

: > "$SUMMARY_FILE"
: > "$UNMAPPED_ALL_FILE"

echo "# Kingshot all-lib import profile summary" >> "$SUMMARY_FILE"
echo "# APK: $APK_PATH" >> "$SUMMARY_FILE"
echo "# Columns: lib_entry mapped_count unmapped_count callbacks_file stubs_file unmapped_file" >> "$SUMMARY_FILE"

lib_count=0
mapped_total=0
unmapped_total=0

while IFS= read -r LIB_ENTRY; do
    [ -z "$LIB_ENTRY" ] && continue
    lib_count=$((lib_count + 1))

    "$ROOT_DIR/scripts/generate_kingshot_import_profile.sh" "$APK_PATH" "$LIB_ENTRY" >/dev/null

    LIB_BASENAME=$(basename "$LIB_ENTRY")
    LIB_NAME=${LIB_BASENAME%.so}
    CALLBACK_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_callbacks.txt"
    STUB_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_stubs.txt"
    UNMAPPED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_unmapped_imports.txt"

    cb_count=$(count_nonempty "$CALLBACK_FILE")
    stub_count=$(count_nonempty "$STUB_FILE")
    mapped_count=$((cb_count + stub_count))
    unmapped_count=$(count_unmapped "$UNMAPPED_FILE")

    mapped_total=$((mapped_total + mapped_count))
    unmapped_total=$((unmapped_total + unmapped_count))

    printf '%s %s %s %s %s %s\n' \
        "$LIB_ENTRY" \
        "$mapped_count" \
        "$unmapped_count" \
        "$CALLBACK_FILE" \
        "$STUB_FILE" \
        "$UNMAPPED_FILE" >> "$SUMMARY_FILE"

    if [ "$unmapped_count" -gt 0 ]; then
        while IFS= read -r sym; do
            [ -z "$sym" ] && continue
            case "$sym" in
                \#*) continue ;;
            esac
            printf '%s:%s\n' "$LIB_ENTRY" "$sym" >> "$UNMAPPED_ALL_FILE"
        done < "$UNMAPPED_FILE"
    fi
done < "$TMP_LIB_LIST"

if [ -s "$UNMAPPED_ALL_FILE" ]; then
    sort -u -o "$UNMAPPED_ALL_FILE" "$UNMAPPED_ALL_FILE"
else
    echo "# all imports mapped" > "$UNMAPPED_ALL_FILE"
fi

echo "Generated Kingshot all-lib import profiles:"
echo "  libs:      $lib_count"
echo "  mapped:    $mapped_total"
echo "  unmapped:  $unmapped_total"
echo "  summary:   $SUMMARY_FILE"
echo "  unmapped:  $UNMAPPED_ALL_FILE"
