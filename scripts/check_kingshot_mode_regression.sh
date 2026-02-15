#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
REPORT_DIR="$ROOT_DIR/reports"
SUMMARY_FILE="$REPORT_DIR/kingshot_mode_regression_summary.txt"
RESTORE_MODE=${KSHOT_PROFILE_MODE:-relaxed}

if [ ! -f "$APK_PATH" ]; then
    echo "APK not found: $APK_PATH" >&2
    exit 1
fi
mkdir -p "$REPORT_DIR"

modes="relaxed strict compat minimal"
: > "$SUMMARY_FILE"
{
    echo "# Kingshot profile-mode regression summary"
    echo "# APK: $APK_PATH"
    echo "# Columns: mode mapped unmapped rejected total coverage_percent"
} >> "$SUMMARY_FILE"

relaxed_mapped=0
strict_mapped=0
compat_mapped=0
last_mode=""

for mode in $modes; do
    "$ROOT_DIR/scripts/generate_kingshot_all_import_profiles.sh" "$APK_PATH" "$mode" >/dev/null

    cov_file="$REPORT_DIR/kingshot_all_import_coverage.txt"
    mapped=$(sed -n 's/^mapped=//p' "$cov_file")
    unmapped=$(sed -n 's/^unmapped=//p' "$cov_file")
    rejected=$(sed -n 's/^rejected=//p' "$cov_file")
    total=$(sed -n 's/^total=//p' "$cov_file")
    coverage=$(sed -n 's/^coverage_percent=//p' "$cov_file")

    [ -z "$mapped" ] && mapped=0
    [ -z "$unmapped" ] && unmapped=0
    [ -z "$rejected" ] && rejected=0
    [ -z "$total" ] && total=0
    [ -z "$coverage" ] && coverage=0.00

    printf '%s %s %s %s %s %s\n' "$mode" "$mapped" "$unmapped" "$rejected" "$total" "$coverage" >> "$SUMMARY_FILE"

    cp "$REPORT_DIR/kingshot_all_import_profiles_summary.txt" "$REPORT_DIR/kingshot_all_import_profiles_summary_${mode}.txt"
    cp "$REPORT_DIR/kingshot_all_import_coverage.txt" "$REPORT_DIR/kingshot_all_import_coverage_${mode}.txt"
    cp "$REPORT_DIR/kingshot_all_unmapped_imports.txt" "$REPORT_DIR/kingshot_all_unmapped_imports_${mode}.txt"
    cp "$REPORT_DIR/kingshot_all_unmapped_top_symbols.txt" "$REPORT_DIR/kingshot_all_unmapped_top_symbols_${mode}.txt"

    case "$mode" in
        relaxed) relaxed_mapped=$mapped ;;
        strict) strict_mapped=$mapped ;;
        compat) compat_mapped=$mapped ;;
    esac
    last_mode=$mode
done

if [ "$relaxed_mapped" -lt "$strict_mapped" ]; then
    echo "Mode regression failed: relaxed mapped ($relaxed_mapped) < strict mapped ($strict_mapped)" >&2
    exit 1
fi
if [ "$compat_mapped" -lt "$strict_mapped" ]; then
    echo "Mode regression failed: compat mapped ($compat_mapped) < strict mapped ($strict_mapped)" >&2
    exit 1
fi

if [ "$RESTORE_MODE" != "$last_mode" ]; then
    "$ROOT_DIR/scripts/generate_kingshot_all_import_profiles.sh" "$APK_PATH" "$RESTORE_MODE" >/dev/null
fi

echo "Kingshot mode regression check passed:"
echo "  summary: $SUMMARY_FILE"
echo "  relaxed mapped: $relaxed_mapped"
echo "  strict mapped:  $strict_mapped"
echo "  compat mapped:  $compat_mapped"
