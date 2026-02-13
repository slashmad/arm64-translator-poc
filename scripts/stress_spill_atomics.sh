#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT_DIR/tiny_dbt"
REPORTS_DIR="$ROOT_DIR/reports"

ITERATIONS="${1:-100}"
SEED="${SEED:-12345}"
STATE="$SEED"
FAIL_LOG="${FAIL_LOG:-$REPORTS_DIR/stress_spill_atomics_fail_$(date +%Y%m%d_%H%M%S).log}"
FAIL_LOG_WRITTEN=0

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -le 0 ]; then
    echo "usage: $0 [positive-iterations]" >&2
    exit 2
fi

hex32() {
    printf "%08X" "$(( $1 & 0xFFFFFFFF ))"
}

rand16() {
    STATE=$(( (1103515245 * STATE + 12345) & 0x7FFFFFFF ))
    printf "%d" "$(( STATE & 0xFFFF ))"
}

rand_off8() {
    local v
    v="$(rand16)"
    printf "%d" "$(( (v % 8191) * 8 ))"
}

op_movz() {
    local rd="$1"
    local imm16="$2"
    hex32 $(( 0xD2800000 | ((imm16 & 0xFFFF) << 5) | (rd & 31) ))
}

op_add_imm() {
    local rd="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rd & 31) ))
}

op_add_reg() {
    local rd="$1"
    local rn="$2"
    local rm="$3"
    hex32 $(( 0x8B000000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31) ))
}

op_str64_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0xF9000000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_ldr64_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0xF9400000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_str32_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0xB9000000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_ldr32_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0xB9400000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_strb_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0x39000000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_ldrb_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0x39400000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_strh_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0x79000000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_ldrh_uimm() {
    local rt="$1"
    local rn="$2"
    local imm12="$3"
    hex32 $(( 0x79400000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31) ))
}

op_swp64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0xF8208000 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_ldadd64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0xF8200000 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_cas64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0xC8A07C00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casa64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0xC8E07C00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casl64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0xC8A0FC00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casal64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0xC8E0FC00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casal32() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0x88E0FC00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casb() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0x08A07C00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_caslb() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0x08A0FC00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casah() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    hex32 $(( 0x48E07C00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casp() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    local sz="$4"
    local l="$5"
    local o0="$6"
    hex32 $(( 0x08207C00 | ((sz & 1) << 30) | ((l & 1) << 22) | ((o0 & 1) << 15) | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31) ))
}

op_casp64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 1 0 0
}

op_casp32() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 0 0 0
}

op_caspa64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 1 1 0
}

op_caspa32() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 0 1 0
}

op_caspl64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 1 0 1
}

op_caspl32() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 0 0 1
}

op_caspal64() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 1 1 1
}

op_caspal32() {
    local rs="$1"
    local rt="$2"
    local rn="$3"
    op_casp "$rs" "$rt" "$rn" 0 1 1
}

op_ret() {
    hex32 0xD65F03C0
}

record_failure() {
    local label="$1"
    local expected="$2"
    local got="$3"
    local opcodes="$4"
    local raw_output="$5"

    mkdir -p "$REPORTS_DIR"
    {
        printf "timestamp: %s\n" "$(date --iso-8601=seconds 2>/dev/null || date)"
        printf "seed: %s\n" "$SEED"
        printf "iterations: %s\n" "$ITERATIONS"
        printf "state: %s\n" "$STATE"
        printf "label: %s\n" "$label"
        printf "expected: %s\n" "$expected"
        printf "got: %s\n" "$got"
        printf "opcodes: %s\n" "$opcodes"
        printf "output:\n%s\n" "$raw_output"
        printf "\n"
    } >> "$FAIL_LOG"
    FAIL_LOG_WRITTEN=1
}

run_and_expect() {
    local expected="$1"
    local label="$2"
    shift 2

    local out got
    out="$("$BIN" "$@")"
    got="$(printf "%s\n" "$out" | sed -n 's/^x0 = \([0-9][0-9]*\).*/\1/p')"

    if [ -z "$got" ]; then
        echo "[$label] failed to parse output: $out" >&2
        record_failure "$label" "$expected" "<parse-error>" "$*" "$out"
        echo "[$label] failure details saved to: $FAIL_LOG" >&2
        return 1
    fi
    if [ "$got" != "$expected" ]; then
        echo "[$label] mismatch: expected=$expected got=$got" >&2
        echo "[$label] opcodes: $*" >&2
        record_failure "$label" "$expected" "$got" "$*" "$out"
        echo "[$label] failure details saved to: $FAIL_LOG" >&2
        return 1
    fi
    return 0
}

if [ ! -x "$BIN" ]; then
    echo "missing executable: $BIN" >&2
    echo "run: make -C \"$ROOT_DIR\" tiny_dbt" >&2
    exit 1
fi

total=0

for ((i = 0; i < ITERATIONS; ++i)); do
    off="$(rand_off8)"
    old="$(rand16)"
    src="$(rand16)"

    # SWP spill: x12 gets old, memory gets src => x0 = old + src
    run_and_expect "$((old + src))" "swp64-spill[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$old")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_movz 13 "$src")" \
        "$(op_swp64 13 12 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # SWP spill with SP base: x12 gets old, memory gets src => x0 = old + src
    run_and_expect "$((old + src))" "swp64-spill-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$old")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_movz 13 "$src")" \
        "$(op_swp64 13 12 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # LDADD spill: x12 gets old, memory gets old+src => x0 = old + (old+src)
    run_and_expect "$((2 * old + src))" "ldadd64-spill[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$old")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_movz 13 "$src")" \
        "$(op_ldadd64 13 12 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # LDADD spill with SP base: x12 gets old, memory gets old+src => x0 = old + (old+src)
    run_and_expect "$((2 * old + src))" "ldadd64-spill-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$old")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_movz 13 "$src")" \
        "$(op_ldadd64 13 12 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CAS spill success: compare matches memory
    newv="$(rand16)"
    run_and_expect "$((old + newv))" "cas64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$old")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_movz 13 "$newv")" \
        "$(op_cas64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CAS spill success with SP base: compare matches memory
    run_and_expect "$((old + newv))" "cas64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$old")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_movz 13 "$newv")" \
        "$(op_cas64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CAS spill fail: compare mismatches memory
    memv="$(rand16)"
    cmpv="$(rand16)"
    if [ "$cmpv" -eq "$memv" ]; then
        cmpv=$(((cmpv + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * memv))" "cas64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$cmpv")" \
        "$(op_movz 13 "$newv")" \
        "$(op_movz 14 "$memv")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_cas64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CAS spill fail with SP base: compare mismatches memory
    run_and_expect "$((2 * memv))" "cas64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$cmpv")" \
        "$(op_movz 13 "$newv")" \
        "$(op_movz 14 "$memv")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_cas64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASP spill success
    old0="$(rand16)"
    old1="$(rand16)"
    new0="$(rand16)"
    new1="$(rand16)"
    run_and_expect "$((old0 + old1 + new0 + new1))" "casp64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$old0")" \
        "$(op_movz 13 "$old1")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_str64_uimm 13 11 1)" \
        "$(op_movz 14 "$new0")" \
        "$(op_movz 15 "$new1")" \
        "$(op_casp64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASP spill success with SP base
    run_and_expect "$((old0 + old1 + new0 + new1))" "casp64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$old0")" \
        "$(op_movz 13 "$old1")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_str64_uimm 13 31 1)" \
        "$(op_movz 14 "$new0")" \
        "$(op_movz 15 "$new1")" \
        "$(op_casp64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASP spill fail
    cmp0="$(rand16)"
    cmp1="$(rand16)"
    mem0="$(rand16)"
    mem1="$(rand16)"
    if [ "$cmp0" -eq "$mem0" ] && [ "$cmp1" -eq "$mem1" ]; then
        cmp1=$(((cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (mem0 + mem1)))" "casp64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$cmp0")" \
        "$(op_movz 13 "$cmp1")" \
        "$(op_movz 14 "$mem0")" \
        "$(op_movz 15 "$mem1")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_str64_uimm 15 11 1)" \
        "$(op_movz 14 "$new0")" \
        "$(op_movz 15 "$new1")" \
        "$(op_casp64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASP spill fail with SP base
    run_and_expect "$((2 * (mem0 + mem1)))" "casp64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$cmp0")" \
        "$(op_movz 13 "$cmp1")" \
        "$(op_movz 14 "$mem0")" \
        "$(op_movz 15 "$mem1")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_str64_uimm 15 31 1)" \
        "$(op_movz 14 "$new0")" \
        "$(op_movz 15 "$new1")" \
        "$(op_casp64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASPA64 pair spill success/fail
    caspa64_old0="$(rand16)"
    caspa64_old1="$(rand16)"
    caspa64_new0="$(rand16)"
    caspa64_new1="$(rand16)"
    run_and_expect "$((caspa64_old0 + caspa64_old1 + caspa64_new0 + caspa64_new1))" "caspa64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspa64_old0")" \
        "$(op_movz 13 "$caspa64_old1")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_str64_uimm 13 11 1)" \
        "$(op_movz 14 "$caspa64_new0")" \
        "$(op_movz 15 "$caspa64_new1")" \
        "$(op_caspa64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((caspa64_old0 + caspa64_old1 + caspa64_new0 + caspa64_new1))" "caspa64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspa64_old0")" \
        "$(op_movz 13 "$caspa64_old1")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_str64_uimm 13 31 1)" \
        "$(op_movz 14 "$caspa64_new0")" \
        "$(op_movz 15 "$caspa64_new1")" \
        "$(op_caspa64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    caspa64_cmp0="$(rand16)"
    caspa64_cmp1="$(rand16)"
    caspa64_mem0="$(rand16)"
    caspa64_mem1="$(rand16)"
    if [ "$caspa64_cmp0" -eq "$caspa64_mem0" ] && [ "$caspa64_cmp1" -eq "$caspa64_mem1" ]; then
        caspa64_cmp1=$(((caspa64_cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (caspa64_mem0 + caspa64_mem1)))" "caspa64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspa64_cmp0")" \
        "$(op_movz 13 "$caspa64_cmp1")" \
        "$(op_movz 14 "$caspa64_mem0")" \
        "$(op_movz 15 "$caspa64_mem1")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_str64_uimm 15 11 1)" \
        "$(op_movz 14 "$caspa64_new0")" \
        "$(op_movz 15 "$caspa64_new1")" \
        "$(op_caspa64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * (caspa64_mem0 + caspa64_mem1)))" "caspa64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspa64_cmp0")" \
        "$(op_movz 13 "$caspa64_cmp1")" \
        "$(op_movz 14 "$caspa64_mem0")" \
        "$(op_movz 15 "$caspa64_mem1")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_str64_uimm 15 31 1)" \
        "$(op_movz 14 "$caspa64_new0")" \
        "$(op_movz 15 "$caspa64_new1")" \
        "$(op_caspa64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASPA32 pair spill success/fail
    caspa32_old0="$(rand16)"
    caspa32_old1="$(rand16)"
    caspa32_new0="$(rand16)"
    caspa32_new1="$(rand16)"
    run_and_expect "$((caspa32_old0 + caspa32_old1 + caspa32_new0 + caspa32_new1))" "caspa32-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspa32_old0")" \
        "$(op_movz 13 "$caspa32_old1")" \
        "$(op_str32_uimm 12 11 0)" \
        "$(op_str32_uimm 13 11 1)" \
        "$(op_movz 14 "$caspa32_new0")" \
        "$(op_movz 15 "$caspa32_new1")" \
        "$(op_caspa32 12 14 11)" \
        "$(op_ldr32_uimm 0 11 0)" \
        "$(op_ldr32_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((caspa32_old0 + caspa32_old1 + caspa32_new0 + caspa32_new1))" "caspa32-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspa32_old0")" \
        "$(op_movz 13 "$caspa32_old1")" \
        "$(op_str32_uimm 12 31 0)" \
        "$(op_str32_uimm 13 31 1)" \
        "$(op_movz 14 "$caspa32_new0")" \
        "$(op_movz 15 "$caspa32_new1")" \
        "$(op_caspa32 12 14 31)" \
        "$(op_ldr32_uimm 0 31 0)" \
        "$(op_ldr32_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    caspa32_cmp0="$(rand16)"
    caspa32_cmp1="$(rand16)"
    caspa32_mem0="$(rand16)"
    caspa32_mem1="$(rand16)"
    if [ "$caspa32_cmp0" -eq "$caspa32_mem0" ] && [ "$caspa32_cmp1" -eq "$caspa32_mem1" ]; then
        caspa32_cmp1=$(((caspa32_cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (caspa32_mem0 + caspa32_mem1)))" "caspa32-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspa32_cmp0")" \
        "$(op_movz 13 "$caspa32_cmp1")" \
        "$(op_movz 14 "$caspa32_mem0")" \
        "$(op_movz 15 "$caspa32_mem1")" \
        "$(op_str32_uimm 14 11 0)" \
        "$(op_str32_uimm 15 11 1)" \
        "$(op_movz 14 "$caspa32_new0")" \
        "$(op_movz 15 "$caspa32_new1")" \
        "$(op_caspa32 12 14 11)" \
        "$(op_ldr32_uimm 0 11 0)" \
        "$(op_ldr32_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * (caspa32_mem0 + caspa32_mem1)))" "caspa32-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspa32_cmp0")" \
        "$(op_movz 13 "$caspa32_cmp1")" \
        "$(op_movz 14 "$caspa32_mem0")" \
        "$(op_movz 15 "$caspa32_mem1")" \
        "$(op_str32_uimm 14 31 0)" \
        "$(op_str32_uimm 15 31 1)" \
        "$(op_movz 14 "$caspa32_new0")" \
        "$(op_movz 15 "$caspa32_new1")" \
        "$(op_caspa32 12 14 31)" \
        "$(op_ldr32_uimm 0 31 0)" \
        "$(op_ldr32_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASPL64 pair spill success/fail
    caspl64_old0="$(rand16)"
    caspl64_old1="$(rand16)"
    caspl64_new0="$(rand16)"
    caspl64_new1="$(rand16)"
    run_and_expect "$((caspl64_old0 + caspl64_old1 + caspl64_new0 + caspl64_new1))" "caspl64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspl64_old0")" \
        "$(op_movz 13 "$caspl64_old1")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_str64_uimm 13 11 1)" \
        "$(op_movz 14 "$caspl64_new0")" \
        "$(op_movz 15 "$caspl64_new1")" \
        "$(op_caspl64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((caspl64_old0 + caspl64_old1 + caspl64_new0 + caspl64_new1))" "caspl64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspl64_old0")" \
        "$(op_movz 13 "$caspl64_old1")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_str64_uimm 13 31 1)" \
        "$(op_movz 14 "$caspl64_new0")" \
        "$(op_movz 15 "$caspl64_new1")" \
        "$(op_caspl64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    caspl64_cmp0="$(rand16)"
    caspl64_cmp1="$(rand16)"
    caspl64_mem0="$(rand16)"
    caspl64_mem1="$(rand16)"
    if [ "$caspl64_cmp0" -eq "$caspl64_mem0" ] && [ "$caspl64_cmp1" -eq "$caspl64_mem1" ]; then
        caspl64_cmp1=$(((caspl64_cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (caspl64_mem0 + caspl64_mem1)))" "caspl64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspl64_cmp0")" \
        "$(op_movz 13 "$caspl64_cmp1")" \
        "$(op_movz 14 "$caspl64_mem0")" \
        "$(op_movz 15 "$caspl64_mem1")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_str64_uimm 15 11 1)" \
        "$(op_movz 14 "$caspl64_new0")" \
        "$(op_movz 15 "$caspl64_new1")" \
        "$(op_caspl64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * (caspl64_mem0 + caspl64_mem1)))" "caspl64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspl64_cmp0")" \
        "$(op_movz 13 "$caspl64_cmp1")" \
        "$(op_movz 14 "$caspl64_mem0")" \
        "$(op_movz 15 "$caspl64_mem1")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_str64_uimm 15 31 1)" \
        "$(op_movz 14 "$caspl64_new0")" \
        "$(op_movz 15 "$caspl64_new1")" \
        "$(op_caspl64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASPL32 pair spill success/fail
    caspl32_old0="$(rand16)"
    caspl32_old1="$(rand16)"
    caspl32_new0="$(rand16)"
    caspl32_new1="$(rand16)"
    run_and_expect "$((caspl32_old0 + caspl32_old1 + caspl32_new0 + caspl32_new1))" "caspl32-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspl32_old0")" \
        "$(op_movz 13 "$caspl32_old1")" \
        "$(op_str32_uimm 12 11 0)" \
        "$(op_str32_uimm 13 11 1)" \
        "$(op_movz 14 "$caspl32_new0")" \
        "$(op_movz 15 "$caspl32_new1")" \
        "$(op_caspl32 12 14 11)" \
        "$(op_ldr32_uimm 0 11 0)" \
        "$(op_ldr32_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((caspl32_old0 + caspl32_old1 + caspl32_new0 + caspl32_new1))" "caspl32-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspl32_old0")" \
        "$(op_movz 13 "$caspl32_old1")" \
        "$(op_str32_uimm 12 31 0)" \
        "$(op_str32_uimm 13 31 1)" \
        "$(op_movz 14 "$caspl32_new0")" \
        "$(op_movz 15 "$caspl32_new1")" \
        "$(op_caspl32 12 14 31)" \
        "$(op_ldr32_uimm 0 31 0)" \
        "$(op_ldr32_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    caspl32_cmp0="$(rand16)"
    caspl32_cmp1="$(rand16)"
    caspl32_mem0="$(rand16)"
    caspl32_mem1="$(rand16)"
    if [ "$caspl32_cmp0" -eq "$caspl32_mem0" ] && [ "$caspl32_cmp1" -eq "$caspl32_mem1" ]; then
        caspl32_cmp1=$(((caspl32_cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (caspl32_mem0 + caspl32_mem1)))" "caspl32-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspl32_cmp0")" \
        "$(op_movz 13 "$caspl32_cmp1")" \
        "$(op_movz 14 "$caspl32_mem0")" \
        "$(op_movz 15 "$caspl32_mem1")" \
        "$(op_str32_uimm 14 11 0)" \
        "$(op_str32_uimm 15 11 1)" \
        "$(op_movz 14 "$caspl32_new0")" \
        "$(op_movz 15 "$caspl32_new1")" \
        "$(op_caspl32 12 14 11)" \
        "$(op_ldr32_uimm 0 11 0)" \
        "$(op_ldr32_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * (caspl32_mem0 + caspl32_mem1)))" "caspl32-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspl32_cmp0")" \
        "$(op_movz 13 "$caspl32_cmp1")" \
        "$(op_movz 14 "$caspl32_mem0")" \
        "$(op_movz 15 "$caspl32_mem1")" \
        "$(op_str32_uimm 14 31 0)" \
        "$(op_str32_uimm 15 31 1)" \
        "$(op_movz 14 "$caspl32_new0")" \
        "$(op_movz 15 "$caspl32_new1")" \
        "$(op_caspl32 12 14 31)" \
        "$(op_ldr32_uimm 0 31 0)" \
        "$(op_ldr32_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASPAL64 pair spill success/fail
    caspal64_old0="$(rand16)"
    caspal64_old1="$(rand16)"
    caspal64_new0="$(rand16)"
    caspal64_new1="$(rand16)"
    run_and_expect "$((caspal64_old0 + caspal64_old1 + caspal64_new0 + caspal64_new1))" "caspal64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspal64_old0")" \
        "$(op_movz 13 "$caspal64_old1")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_str64_uimm 13 11 1)" \
        "$(op_movz 14 "$caspal64_new0")" \
        "$(op_movz 15 "$caspal64_new1")" \
        "$(op_caspal64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((caspal64_old0 + caspal64_old1 + caspal64_new0 + caspal64_new1))" "caspal64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspal64_old0")" \
        "$(op_movz 13 "$caspal64_old1")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_str64_uimm 13 31 1)" \
        "$(op_movz 14 "$caspal64_new0")" \
        "$(op_movz 15 "$caspal64_new1")" \
        "$(op_caspal64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    caspal64_cmp0="$(rand16)"
    caspal64_cmp1="$(rand16)"
    caspal64_mem0="$(rand16)"
    caspal64_mem1="$(rand16)"
    if [ "$caspal64_cmp0" -eq "$caspal64_mem0" ] && [ "$caspal64_cmp1" -eq "$caspal64_mem1" ]; then
        caspal64_cmp1=$(((caspal64_cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (caspal64_mem0 + caspal64_mem1)))" "caspal64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspal64_cmp0")" \
        "$(op_movz 13 "$caspal64_cmp1")" \
        "$(op_movz 14 "$caspal64_mem0")" \
        "$(op_movz 15 "$caspal64_mem1")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_str64_uimm 15 11 1)" \
        "$(op_movz 14 "$caspal64_new0")" \
        "$(op_movz 15 "$caspal64_new1")" \
        "$(op_caspal64 12 14 11)" \
        "$(op_ldr64_uimm 0 11 0)" \
        "$(op_ldr64_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * (caspal64_mem0 + caspal64_mem1)))" "caspal64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspal64_cmp0")" \
        "$(op_movz 13 "$caspal64_cmp1")" \
        "$(op_movz 14 "$caspal64_mem0")" \
        "$(op_movz 15 "$caspal64_mem1")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_str64_uimm 15 31 1)" \
        "$(op_movz 14 "$caspal64_new0")" \
        "$(op_movz 15 "$caspal64_new1")" \
        "$(op_caspal64 12 14 31)" \
        "$(op_ldr64_uimm 0 31 0)" \
        "$(op_ldr64_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASPAL32 pair spill success/fail
    caspal32_old0="$(rand16)"
    caspal32_old1="$(rand16)"
    caspal32_new0="$(rand16)"
    caspal32_new1="$(rand16)"
    run_and_expect "$((caspal32_old0 + caspal32_old1 + caspal32_new0 + caspal32_new1))" "caspal32-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspal32_old0")" \
        "$(op_movz 13 "$caspal32_old1")" \
        "$(op_str32_uimm 12 11 0)" \
        "$(op_str32_uimm 13 11 1)" \
        "$(op_movz 14 "$caspal32_new0")" \
        "$(op_movz 15 "$caspal32_new1")" \
        "$(op_caspal32 12 14 11)" \
        "$(op_ldr32_uimm 0 11 0)" \
        "$(op_ldr32_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((caspal32_old0 + caspal32_old1 + caspal32_new0 + caspal32_new1))" "caspal32-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspal32_old0")" \
        "$(op_movz 13 "$caspal32_old1")" \
        "$(op_str32_uimm 12 31 0)" \
        "$(op_str32_uimm 13 31 1)" \
        "$(op_movz 14 "$caspal32_new0")" \
        "$(op_movz 15 "$caspal32_new1")" \
        "$(op_caspal32 12 14 31)" \
        "$(op_ldr32_uimm 0 31 0)" \
        "$(op_ldr32_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    caspal32_cmp0="$(rand16)"
    caspal32_cmp1="$(rand16)"
    caspal32_mem0="$(rand16)"
    caspal32_mem1="$(rand16)"
    if [ "$caspal32_cmp0" -eq "$caspal32_mem0" ] && [ "$caspal32_cmp1" -eq "$caspal32_mem1" ]; then
        caspal32_cmp1=$(((caspal32_cmp1 + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * (caspal32_mem0 + caspal32_mem1)))" "caspal32-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$caspal32_cmp0")" \
        "$(op_movz 13 "$caspal32_cmp1")" \
        "$(op_movz 14 "$caspal32_mem0")" \
        "$(op_movz 15 "$caspal32_mem1")" \
        "$(op_str32_uimm 14 11 0)" \
        "$(op_str32_uimm 15 11 1)" \
        "$(op_movz 14 "$caspal32_new0")" \
        "$(op_movz 15 "$caspal32_new1")" \
        "$(op_caspal32 12 14 11)" \
        "$(op_ldr32_uimm 0 11 0)" \
        "$(op_ldr32_uimm 1 11 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * (caspal32_mem0 + caspal32_mem1)))" "caspal32-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$caspal32_cmp0")" \
        "$(op_movz 13 "$caspal32_cmp1")" \
        "$(op_movz 14 "$caspal32_mem0")" \
        "$(op_movz 15 "$caspal32_mem1")" \
        "$(op_str32_uimm 14 31 0)" \
        "$(op_str32_uimm 15 31 1)" \
        "$(op_movz 14 "$caspal32_new0")" \
        "$(op_movz 15 "$caspal32_new1")" \
        "$(op_caspal32 12 14 31)" \
        "$(op_ldr32_uimm 0 31 0)" \
        "$(op_ldr32_uimm 1 31 1)" \
        "$(op_add_reg 0 0 1)" \
        "$(op_add_reg 0 0 12)" \
        "$(op_add_reg 0 0 13)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASA64 spill success/fail
    casa_old="$(rand16)"
    casa_new="$(rand16)"
    run_and_expect "$((casa_old + casa_new))" "casa64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casa_old")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_movz 13 "$casa_new")" \
        "$(op_casa64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((casa_old + casa_new))" "casa64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casa_old")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_movz 13 "$casa_new")" \
        "$(op_casa64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    casa_mem="$(rand16)"
    casa_cmp="$(rand16)"
    if [ "$casa_cmp" -eq "$casa_mem" ]; then
        casa_cmp=$(((casa_cmp + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * casa_mem))" "casa64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casa_cmp")" \
        "$(op_movz 13 "$casa_new")" \
        "$(op_movz 14 "$casa_mem")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_casa64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * casa_mem))" "casa64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casa_cmp")" \
        "$(op_movz 13 "$casa_new")" \
        "$(op_movz 14 "$casa_mem")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_casa64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASL64 spill success/fail
    casl_old="$(rand16)"
    casl_new="$(rand16)"
    run_and_expect "$((casl_old + casl_new))" "casl64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casl_old")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_movz 13 "$casl_new")" \
        "$(op_casl64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((casl_old + casl_new))" "casl64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casl_old")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_movz 13 "$casl_new")" \
        "$(op_casl64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    casl_mem="$(rand16)"
    casl_cmp="$(rand16)"
    if [ "$casl_cmp" -eq "$casl_mem" ]; then
        casl_cmp=$(((casl_cmp + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * casl_mem))" "casl64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casl_cmp")" \
        "$(op_movz 13 "$casl_new")" \
        "$(op_movz 14 "$casl_mem")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_casl64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * casl_mem))" "casl64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casl_cmp")" \
        "$(op_movz 13 "$casl_new")" \
        "$(op_movz 14 "$casl_mem")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_casl64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASAL64 spill success/fail
    casal_old="$(rand16)"
    casal_new="$(rand16)"
    run_and_expect "$((casal_old + casal_new))" "casal64-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casal_old")" \
        "$(op_str64_uimm 12 11 0)" \
        "$(op_movz 13 "$casal_new")" \
        "$(op_casal64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((casal_old + casal_new))" "casal64-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casal_old")" \
        "$(op_str64_uimm 12 31 0)" \
        "$(op_movz 13 "$casal_new")" \
        "$(op_casal64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    casal_mem="$(rand16)"
    casal_cmp="$(rand16)"
    if [ "$casal_cmp" -eq "$casal_mem" ]; then
        casal_cmp=$(((casal_cmp + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * casal_mem))" "casal64-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casal_cmp")" \
        "$(op_movz 13 "$casal_new")" \
        "$(op_movz 14 "$casal_mem")" \
        "$(op_str64_uimm 14 11 0)" \
        "$(op_casal64 12 13 11)" \
        "$(op_ldr64_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * casal_mem))" "casal64-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casal_cmp")" \
        "$(op_movz 13 "$casal_new")" \
        "$(op_movz 14 "$casal_mem")" \
        "$(op_str64_uimm 14 31 0)" \
        "$(op_casal64 12 13 31)" \
        "$(op_ldr64_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASAL32 spill success/fail
    casal32_old="$(rand16)"
    casal32_new="$(rand16)"
    run_and_expect "$((casal32_old + casal32_new))" "casal32-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casal32_old")" \
        "$(op_str32_uimm 12 11 0)" \
        "$(op_movz 13 "$casal32_new")" \
        "$(op_casal32 12 13 11)" \
        "$(op_ldr32_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((casal32_old + casal32_new))" "casal32-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casal32_old")" \
        "$(op_str32_uimm 12 31 0)" \
        "$(op_movz 13 "$casal32_new")" \
        "$(op_casal32 12 13 31)" \
        "$(op_ldr32_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    casal32_mem="$(rand16)"
    casal32_cmp="$(rand16)"
    if [ "$casal32_cmp" -eq "$casal32_mem" ]; then
        casal32_cmp=$(((casal32_cmp + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * casal32_mem))" "casal32-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casal32_cmp")" \
        "$(op_movz 13 "$casal32_new")" \
        "$(op_movz 14 "$casal32_mem")" \
        "$(op_str32_uimm 14 11 0)" \
        "$(op_casal32 12 13 11)" \
        "$(op_ldr32_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * casal32_mem))" "casal32-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casal32_cmp")" \
        "$(op_movz 13 "$casal32_new")" \
        "$(op_movz 14 "$casal32_mem")" \
        "$(op_str32_uimm 14 31 0)" \
        "$(op_casal32 12 13 31)" \
        "$(op_ldr32_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASB/CASLB spill success/fail
    casb_old=$(( $(rand16) & 0xFF ))
    casb_new=$(( $(rand16) & 0xFF ))
    run_and_expect "$((casb_old + casb_new))" "casb-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casb_old")" \
        "$(op_strb_uimm 12 11 0)" \
        "$(op_movz 13 "$casb_new")" \
        "$(op_casb 12 13 11)" \
        "$(op_ldrb_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((casb_old + casb_new))" "casb-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casb_old")" \
        "$(op_strb_uimm 12 31 0)" \
        "$(op_movz 13 "$casb_new")" \
        "$(op_casb 12 13 31)" \
        "$(op_ldrb_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    casb_mem=$(( $(rand16) & 0xFF ))
    casb_cmp=$(( $(rand16) & 0xFF ))
    if [ "$casb_cmp" -eq "$casb_mem" ]; then
        casb_cmp=$(((casb_cmp + 1) & 0xFF))
    fi
    run_and_expect "$((2 * casb_mem))" "caslb-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casb_cmp")" \
        "$(op_movz 13 "$casb_new")" \
        "$(op_movz 14 "$casb_mem")" \
        "$(op_strb_uimm 14 11 0)" \
        "$(op_caslb 12 13 11)" \
        "$(op_ldrb_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * casb_mem))" "caslb-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casb_cmp")" \
        "$(op_movz 13 "$casb_new")" \
        "$(op_movz 14 "$casb_mem")" \
        "$(op_strb_uimm 14 31 0)" \
        "$(op_caslb 12 13 31)" \
        "$(op_ldrb_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    # CASAH spill success/fail
    casah_old="$(rand16)"
    casah_new="$(rand16)"
    run_and_expect "$((casah_old + casah_new))" "casah-spill-success[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casah_old")" \
        "$(op_strh_uimm 12 11 0)" \
        "$(op_movz 13 "$casah_new")" \
        "$(op_casah 12 13 11)" \
        "$(op_ldrh_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((casah_old + casah_new))" "casah-spill-success-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casah_old")" \
        "$(op_strh_uimm 12 31 0)" \
        "$(op_movz 13 "$casah_new")" \
        "$(op_casah 12 13 31)" \
        "$(op_ldrh_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    casah_mem="$(rand16)"
    casah_cmp="$(rand16)"
    if [ "$casah_cmp" -eq "$casah_mem" ]; then
        casah_cmp=$(((casah_cmp + 1) & 0xFFFF))
    fi
    run_and_expect "$((2 * casah_mem))" "casah-spill-fail[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_movz 12 "$casah_cmp")" \
        "$(op_movz 13 "$casah_new")" \
        "$(op_movz 14 "$casah_mem")" \
        "$(op_strh_uimm 14 11 0)" \
        "$(op_casah 12 13 11)" \
        "$(op_ldrh_uimm 14 11 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))

    run_and_expect "$((2 * casah_mem))" "casah-spill-fail-sp[$i]" \
        "$(op_movz 11 "$off")" \
        "$(op_add_imm 31 11 0)" \
        "$(op_movz 12 "$casah_cmp")" \
        "$(op_movz 13 "$casah_new")" \
        "$(op_movz 14 "$casah_mem")" \
        "$(op_strh_uimm 14 31 0)" \
        "$(op_casah 12 13 31)" \
        "$(op_ldrh_uimm 14 31 0)" \
        "$(op_add_reg 0 12 14)" \
        "$(op_ret)"
    total=$((total + 1))
done

printf "stress_spill_atomics: ok (%d cases, seed=%d, iterations=%d)\n" "$total" "$SEED" "$ITERATIONS"
