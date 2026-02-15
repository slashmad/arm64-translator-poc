#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
PROFILE_MODE=${2:-relaxed}
PROFILE_DIR="$ROOT_DIR/profiles"
REPORT_DIR="$ROOT_DIR/reports"
SUMMARY_FILE="$REPORT_DIR/kingshot_all_import_profiles_summary.txt"
UNMAPPED_ALL_FILE="$REPORT_DIR/kingshot_all_unmapped_imports.txt"
UNMAPPED_TOP_FILE="$REPORT_DIR/kingshot_all_unmapped_top_symbols.txt"
REJECTED_ALL_FILE="$REPORT_DIR/kingshot_all_rejected_import_symbols.txt"
REJECTED_TOP_FILE="$REPORT_DIR/kingshot_all_rejected_top_symbols.txt"
COVERAGE_FILE="$REPORT_DIR/kingshot_all_import_coverage.txt"
NEXT_CALLBACKS_FILE="$REPORT_DIR/kingshot_next_callbacks.txt"

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
case "$PROFILE_MODE" in
    relaxed|strict|compat)
        ;;
    *)
        echo "Invalid profile mode: $PROFILE_MODE (expected relaxed|strict|compat)" >&2
        exit 1
        ;;
esac

mkdir -p "$PROFILE_DIR" "$REPORT_DIR"

TMP_LIB_LIST=$(mktemp /tmp/kingshot_lib_list.XXXXXX.txt)
TMP_WEIGHTS=$(mktemp /tmp/kingshot_weights.XXXXXX.txt)
trap 'rm -f "$TMP_LIB_LIST" "$TMP_WEIGHTS"' EXIT INT TERM

unzip -Z1 "$APK_PATH" | awk '/^lib\/arm64-v8a\/.*\.so$/ {print}' | sort -u > "$TMP_LIB_LIST"
if [ ! -s "$TMP_LIB_LIST" ]; then
    echo "No arm64 shared libraries found in APK: $APK_PATH" >&2
    exit 1
fi

: > "$SUMMARY_FILE"
: > "$UNMAPPED_ALL_FILE"
: > "$REJECTED_ALL_FILE"

echo "# Kingshot all-lib import profile summary" >> "$SUMMARY_FILE"
echo "# APK: $APK_PATH" >> "$SUMMARY_FILE"
echo "# Mode: $PROFILE_MODE" >> "$SUMMARY_FILE"
echo "# Columns: lib_entry mapped_count unmapped_count rejected_count callbacks_file stubs_file unmapped_file rejected_file" >> "$SUMMARY_FILE"

lib_count=0
mapped_total=0
unmapped_total=0
rejected_total=0

while IFS= read -r LIB_ENTRY; do
    [ -z "$LIB_ENTRY" ] && continue
    lib_count=$((lib_count + 1))

    "$ROOT_DIR/scripts/generate_kingshot_import_profile.sh" "$APK_PATH" "$LIB_ENTRY" "$PROFILE_MODE" >/dev/null

    LIB_BASENAME=$(basename "$LIB_ENTRY")
    LIB_NAME=${LIB_BASENAME%.so}
    CALLBACK_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_callbacks.txt"
    STUB_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_stubs.txt"
    UNMAPPED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_unmapped_imports.txt"
    REJECTED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_rejected_import_symbols.txt"

    cb_count=$(count_nonempty "$CALLBACK_FILE")
    stub_count=$(count_nonempty "$STUB_FILE")
    mapped_count=$((cb_count + stub_count))
    unmapped_count=$(count_unmapped "$UNMAPPED_FILE")
    rejected_count=$(count_nonempty "$REJECTED_FILE")

    mapped_total=$((mapped_total + mapped_count))
    unmapped_total=$((unmapped_total + unmapped_count))
    rejected_total=$((rejected_total + rejected_count))

    printf '%s %s %s %s %s %s %s %s\n' \
        "$LIB_ENTRY" \
        "$mapped_count" \
        "$unmapped_count" \
        "$rejected_count" \
        "$CALLBACK_FILE" \
        "$STUB_FILE" \
        "$UNMAPPED_FILE" \
        "$REJECTED_FILE" >> "$SUMMARY_FILE"

    if [ "$unmapped_count" -gt 0 ]; then
        while IFS= read -r sym; do
            [ -z "$sym" ] && continue
            case "$sym" in
                \#*) continue ;;
            esac
            printf '%s:%s\n' "$LIB_ENTRY" "$sym" >> "$UNMAPPED_ALL_FILE"
        done < "$UNMAPPED_FILE"
    fi
    if [ "$rejected_count" -gt 0 ]; then
        while IFS= read -r sym; do
            [ -z "$sym" ] && continue
            printf '%s:%s\n' "$LIB_ENTRY" "$sym" >> "$REJECTED_ALL_FILE"
        done < "$REJECTED_FILE"
    fi
done < "$TMP_LIB_LIST"

if [ -s "$UNMAPPED_ALL_FILE" ]; then
    sort -u -o "$UNMAPPED_ALL_FILE" "$UNMAPPED_ALL_FILE"
    awk -F: '{print $2}' "$UNMAPPED_ALL_FILE" \
        | sort \
        | uniq -c \
        | sort -nr \
        | awk '{printf "%s %s\n", $1, $2}' > "$UNMAPPED_TOP_FILE"
else
    echo "# all imports mapped" > "$UNMAPPED_ALL_FILE"
    echo "# all imports mapped" > "$UNMAPPED_TOP_FILE"
fi

if [ -s "$REJECTED_ALL_FILE" ]; then
    sort -u -o "$REJECTED_ALL_FILE" "$REJECTED_ALL_FILE"
    awk -F: '{print $2}' "$REJECTED_ALL_FILE" \
        | sort \
        | uniq -c \
        | sort -nr \
        | awk '{printf "%s %s\n", $1, $2}' > "$REJECTED_TOP_FILE"
else
    echo "# no rejected symbols" > "$REJECTED_ALL_FILE"
    echo "# no rejected symbols" > "$REJECTED_TOP_FILE"
fi

awk 'NF >= 3 && $1 ~ /^lib\/arm64-v8a\/.*\.so$/ {print $1, $3}' "$SUMMARY_FILE" > "$TMP_WEIGHTS"
if [ -s "$UNMAPPED_ALL_FILE" ] && ! grep -q '^# all imports mapped$' "$UNMAPPED_ALL_FILE"; then
    awk -F: '
        NR == FNR {
            weights[$1] = $2 + 0;
            next;
        }
        {
            lib = $1;
            sym = $2;
            if (sym == "" || sym ~ /^#/) {
                next;
            }
            score[sym] += (weights[lib] > 0 ? weights[lib] : 1);
            freq[sym] += 1;
        }
        END {
            for (s in score) {
                printf "%.0f %d %s\n", score[s], freq[s], s;
            }
        }
    ' "$TMP_WEIGHTS" "$UNMAPPED_ALL_FILE" | sort -k1,1nr -k2,2nr > "$NEXT_CALLBACKS_FILE"
else
    echo "# all imports mapped" > "$NEXT_CALLBACKS_FILE"
fi

total_count=$((mapped_total + unmapped_total))
if [ "$total_count" -gt 0 ]; then
    coverage_pct=$(awk -v m="$mapped_total" -v t="$total_count" 'BEGIN { printf "%.2f", (100.0*m)/t }')
else
    coverage_pct="0.00"
fi
{
    echo "libs=$lib_count"
    echo "mapped=$mapped_total"
    echo "unmapped=$unmapped_total"
    echo "rejected=$rejected_total"
    echo "total=$total_count"
    echo "mode=$PROFILE_MODE"
    echo "coverage_percent=$coverage_pct"
} > "$COVERAGE_FILE"

echo "Generated Kingshot all-lib import profiles:"
echo "  libs:      $lib_count"
echo "  mode:      $PROFILE_MODE"
echo "  mapped:    $mapped_total"
echo "  unmapped:  $unmapped_total"
echo "  rejected:  $rejected_total"
echo "  summary:   $SUMMARY_FILE"
echo "  unmapped:  $UNMAPPED_ALL_FILE"
echo "  top:       $UNMAPPED_TOP_FILE"
echo "  rejected:  $REJECTED_ALL_FILE"
echo "  rej-top:   $REJECTED_TOP_FILE"
echo "  next:      $NEXT_CALLBACKS_FILE"
echo "  coverage:  $COVERAGE_FILE (${coverage_pct}%)"
