#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
REPORT_DIR=${1:-"$ROOT_DIR/reports"}
OUT_FILE="$REPORT_DIR/unsupported_top20_summary.txt"

mkdir -p "$REPORT_DIR"

TMP_RUNTIME=$(mktemp /tmp/unsupported_runtime.XXXXXX)
TMP_SORTED=$(mktemp /tmp/unsupported_sorted.XXXXXX)
trap 'rm -f "$TMP_RUNTIME" "$TMP_SORTED"' EXIT INT TERM

find "$REPORT_DIR" -maxdepth 1 -type f -name '*_unsupported_smoke.txt' | sort > "$TMP_RUNTIME"

runtime_rows=0
if [ -s "$TMP_RUNTIME" ]; then
    awk '
        {
            for (i = 1; i <= NF; ++i) {
                if ($i ~ /^insn=0x[0-9a-fA-F]+$/) {
                    gsub(/^insn=/, "", $i);
                    print tolower($i);
                }
            }
        }
    ' $(cat "$TMP_RUNTIME") | sort | uniq -c | sort -nr > "$TMP_SORTED" || true

    if [ -s "$TMP_SORTED" ]; then
        runtime_rows=$(wc -l < "$TMP_SORTED" | tr -d ' ')
    fi
fi

{
    echo "# Unsupported opcode triage"
    echo "# Generated: $(date -Iseconds)"
    echo "# Source reports dir: $REPORT_DIR"
    echo

    if [ "$runtime_rows" -gt 0 ]; then
        echo "mode=runtime"
        echo "runtime_unique_opcodes=$runtime_rows"
        echo "top20_runtime_unsupported:"
        head -n 20 "$TMP_SORTED" | awk '{printf "- count=%s insn=%s\n", $1, $2}'
    else
        echo "mode=fallback_inventory"
        echo "reason=no non-empty *_unsupported_smoke.txt entries"

        latest_inventory=$(ls -1 "$REPORT_DIR"/mnemonic_inventory_*.txt 2>/dev/null | tail -n 1 || true)
        if [ -n "$latest_inventory" ] && [ -f "$latest_inventory" ]; then
            echo "inventory_file=$latest_inventory"
            echo "top20_unmatched_prefixes_from_combined:"
            awk '
                /^== combined ==/ { in_combined = 1; next }
                in_combined && /^Top 20 unmatched prefixes \(11 high bits\):/ { in_top20 = 1; next }
                in_top20 {
                    if ($0 ~ /^[[:space:]]*[0-9]+\./) {
                        line = $0
                        gsub(/^[[:space:]]+/, "", line)
                        print "- " line
                        seen++
                        if (seen >= 20) {
                            exit
                        }
                    }
                }
            ' "$latest_inventory"
            echo
            echo "note=inventory prefixes include possible embedded data words; prioritize runtime unsupported logs when available"
        else
            echo "inventory_file=<none>"
            echo "top20_unmatched_prefixes_from_combined: <unavailable>"
        fi
    fi
} > "$OUT_FILE"

echo "Unsupported triage report written: $OUT_FILE"
