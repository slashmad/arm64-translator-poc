#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
OUT_DIR=${2:-"$ROOT_DIR/reports"}
TOOL="$SCRIPT_DIR/mnemonic_inventory_tool"
EMIT_FILE="$ROOT_DIR/tiny_dbt_runtime_emit.inc.c"

if [ ! -f "$APK_PATH" ]; then
    echo "error: apk not found: $APK_PATH" >&2
    exit 1
fi

if [ ! -f "$EMIT_FILE" ]; then
    echo "error: emit file not found: $EMIT_FILE" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

if [ ! -x "$TOOL" ]; then
    cc -O2 -Wall -Wextra -Werror -std=c11 -o "$TOOL" "$SCRIPT_DIR/mnemonic_inventory.c"
fi

TMPDIR=$(mktemp -d /tmp/mnemonic_inventory.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

RULES_FILE="$TMPDIR/decode_named_rules.txt"
awk '
function trim(s) {
    gsub(/^[[:space:]]+/, "", s);
    gsub(/[[:space:]]+$/, "", s);
    return s;
}
function sanitize(label, tok, n, arr) {
    label = trim(label);
    gsub(/^[*[:space:]]+/, "", label);
    gsub(/[[:space:]]+/, " ", label);
    n = split(label, arr, /[^A-Za-z0-9_.\/]+/);
    tok = arr[1];
    gsub(/\//, "_", tok);
    return tok;
}
{
    line = $0;

    if (in_comment) {
        part = line;
        if (index(part, "*/")) {
            sub(/\*\/.*/, "", part);
            comment = comment " " part;
            last_comment = comment;
            comment = "";
            in_comment = 0;
        } else {
            comment = comment " " part;
        }
    }

    if (!in_comment && index(line, "/*")) {
        part = line;
        sub(/^.*\/\*/, "", part);
        if (index(part, "*/")) {
            sub(/\*\/.*/, "", part);
            last_comment = part;
        } else {
            comment = part;
            in_comment = 1;
        }
    }

    rest = line;
    while (match(rest, /\(insn & (0x[0-9A-Fa-f]+)u\) == (0x[0-9A-Fa-f]+)u/, m)) {
        label = sanitize(last_comment);
        if (label == "") {
            rule_idx++;
            label = sprintf("RULE_%d", rule_idx);
        }
        printf("%s %s %s\n", m[1], m[2], label);
        rest = substr(rest, RSTART + RLENGTH);
    }

    rest = line;
    while (match(rest, /insn == (0x[0-9A-Fa-f]+)u/, m)) {
        label = sanitize(last_comment);
        if (label == "") {
            rule_idx++;
            label = sprintf("RULE_%d", rule_idx);
        }
        printf("0xFFFFFFFF %s %s\n", m[1], label);
        rest = substr(rest, RSTART + RLENGTH);
    }
}
' "$EMIT_FILE" > "$RULES_FILE"

extract_so() {
    libname=$1
    outpath=$2
    unzip -p "$APK_PATH" "lib/arm64-v8a/$libname" > "$outpath"
}

extract_exec_sections() {
    so_path=$1
    prefix=$2
    list_file=$3
    meta_file=$TMPDIR/"$prefix"_sections_meta.txt
    idx=0

    : > "$list_file"
    readelf -S -W "$so_path" \
        | awk '$1=="[" && $4=="PROGBITS" && index($9, "X") && ($3 == "il2cpp" || $3 == ".text" || $3 ~ /text/) {print $3, $6, $7}' > "$meta_file"

    while read -r name off size; do
        off_dec=$((16#$off))
        size_dec=$((16#$size))
        sec_path=$TMPDIR/"$prefix"_sec_"$idx".bin
        idx=$((idx + 1))

        if [ "$size_dec" -lt 4 ]; then
            continue
        fi
        dd if="$so_path" of="$sec_path" bs=1 skip="$off_dec" count="$size_dec" status=none
        printf '%s\n' "$sec_path" >> "$list_file"
    done < "$meta_file"
}

run_inventory_for() {
    list_file=$1
    out_file=$2

    set -- $(cat "$list_file")
    if [ "$#" -eq 0 ]; then
        echo "error: no executable sections found" >&2
        exit 1
    fi
    "$TOOL" "$RULES_FILE" "$@" > "$out_file"
}

IL2CPP_SO="$TMPDIR/libil2cpp.so"
UNITY_SO="$TMPDIR/libunity.so"
IL2CPP_LIST="$TMPDIR/libil2cpp_sections.txt"
UNITY_LIST="$TMPDIR/libunity_sections.txt"
ALL_LIST="$TMPDIR/all_sections.txt"
IL2CPP_REPORT="$TMPDIR/libil2cpp_report.txt"
UNITY_REPORT="$TMPDIR/libunity_report.txt"
ALL_REPORT="$TMPDIR/all_report.txt"

extract_so "libil2cpp.so" "$IL2CPP_SO"
extract_so "libunity.so" "$UNITY_SO"

extract_exec_sections "$IL2CPP_SO" "libil2cpp" "$IL2CPP_LIST"
extract_exec_sections "$UNITY_SO" "libunity" "$UNITY_LIST"
cat "$IL2CPP_LIST" "$UNITY_LIST" > "$ALL_LIST"

run_inventory_for "$IL2CPP_LIST" "$IL2CPP_REPORT"
run_inventory_for "$UNITY_LIST" "$UNITY_REPORT"
run_inventory_for "$ALL_LIST" "$ALL_REPORT"

timestamp=$(date +%Y%m%d_%H%M%S)
REPORT_PATH="$OUT_DIR/mnemonic_inventory_$timestamp.txt"

{
    echo "mnemonic inventory report"
    echo "date: $(date -Iseconds)"
    echo "apk: $APK_PATH"
    echo "rules_file: $RULES_FILE"
    echo
    echo "== libil2cpp.so =="
    cat "$IL2CPP_REPORT"
    echo
    echo "== libunity.so =="
    cat "$UNITY_REPORT"
    echo
    echo "== combined =="
    cat "$ALL_REPORT"
} > "$REPORT_PATH"

echo "$REPORT_PATH"
