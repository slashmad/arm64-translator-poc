#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
COVERAGE_FILE=${1:-"$ROOT_DIR/reports/kingshot_all_import_coverage.txt"}
BASELINE_FILE=${2:-"$ROOT_DIR/kingshot_coverage_baseline.txt"}

extract_pct() {
    file=$1
    sed -n 's/^coverage_percent=//p' "$file" | head -n 1
}

if [ ! -f "$COVERAGE_FILE" ]; then
    echo "Coverage file not found: $COVERAGE_FILE" >&2
    echo "Run: make run-kingshot-import-profile-all" >&2
    exit 1
fi
if [ ! -f "$BASELINE_FILE" ]; then
    echo "Baseline file not found: $BASELINE_FILE" >&2
    exit 1
fi

current=$(extract_pct "$COVERAGE_FILE")
baseline=$(extract_pct "$BASELINE_FILE")

if [ -z "$current" ] || [ -z "$baseline" ]; then
    echo "Failed to parse coverage_percent from files" >&2
    echo "  coverage: $COVERAGE_FILE" >&2
    echo "  baseline: $BASELINE_FILE" >&2
    exit 1
fi

if awk -v c="$current" -v b="$baseline" 'BEGIN { exit !(c + 0 >= b + 0) }'; then
    echo "Coverage gate passed: current=${current}% baseline=${baseline}%"
    exit 0
fi

echo "Coverage gate failed: current=${current}% baseline=${baseline}%" >&2
exit 1
