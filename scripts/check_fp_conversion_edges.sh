#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TINY_DBT="$ROOT_DIR/tiny_dbt"

if [ ! -x "$TINY_DBT" ]; then
    echo "tiny_dbt not built. Run: make tiny_dbt" >&2
    exit 1
fi

pass_count=0

run_expect_x0() {
    label=$1
    expected=$2
    shift 2

    set +e
    out=$($TINY_DBT "$@" 2>&1)
    rc=$?
    set -e

    if [ "$rc" -ne 0 ]; then
        echo "[$label] command failed (rc=$rc)" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi

    got=$(printf '%s\n' "$out" | sed -n 's/^x0 = \([0-9][0-9]*\).*/\1/p' | tail -n 1)
    if [ -z "$got" ]; then
        echo "[$label] could not parse x0 from output" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi

    if [ "$got" != "$expected" ]; then
        echo "[$label] mismatch: expected=$expected got=$got" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi

    pass_count=$((pass_count + 1))
}

# Round-trip sanity: SCVTF/UCVTF + FCVTZS/FCVTZU
run_expect_x0 scvtf_fcvtzs_rt64 42 \
    --set-reg x0=42 \
    9E620001 9E780020 D65F03C0

run_expect_x0 ucvtf_fcvtzu_rt64_hi 9223372036854775808 \
    --set-reg x0=0x8000000000000000 \
    9E630001 9E790020 D65F03C0

run_expect_x0 ucvtf_fcvtzu_rt64_max 18446744073709551615 \
    --set-reg x0=0xFFFFFFFFFFFFFFFF \
    9E630001 9E790020 D65F03C0

run_expect_x0 scvtf_fcvtzs_rt32 123 \
    --set-reg x0=123 \
    1E220001 1E380020 D65F03C0

run_expect_x0 ucvtf_fcvtzu_rt32_max 4294967295 \
    --set-reg x0=0xFFFFFFFF \
    1E230001 1E390020 D65F03C0

# FCVTZS 64-bit edges (D -> X)
run_expect_x0 fcvtzs64_nan 0 \
    --set-reg x0=0x7FF8000000000000 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_pos_inf 9223372036854775807 \
    --set-reg x0=0x7FF0000000000000 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_neg_inf 9223372036854775808 \
    --set-reg x0=0xFFF0000000000000 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_plus_2p63_clamp 9223372036854775807 \
    --set-reg x0=0x43E0000000000000 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_minus_2p63_edge 9223372036854775808 \
    --set-reg x0=0xC3E0000000000000 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_trunc_pos 3 \
    --set-reg x0=0x400F333333333333 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_trunc_neg 18446744073709551613 \
    --set-reg x0=0xC00F333333333333 \
    9E670001 9E780020 D65F03C0

run_expect_x0 fcvtzs64_subnormal 0 \
    --set-reg x0=0x0000000000000001 \
    9E670001 9E780020 D65F03C0

# FCVTZU 64-bit edges (D -> X)
run_expect_x0 fcvtzu64_nan 0 \
    --set-reg x0=0x7FF8000000000000 \
    9E670001 9E790020 D65F03C0

run_expect_x0 fcvtzu64_neg_to_zero 0 \
    --set-reg x0=0xC00F333333333333 \
    9E670001 9E790020 D65F03C0

run_expect_x0 fcvtzu64_pos_inf 18446744073709551615 \
    --set-reg x0=0x7FF0000000000000 \
    9E670001 9E790020 D65F03C0

run_expect_x0 fcvtzu64_ge_2p64 18446744073709551615 \
    --set-reg x0=0x43F0000000000000 \
    9E670001 9E790020 D65F03C0

run_expect_x0 fcvtzu64_subnormal 0 \
    --set-reg x0=0x0000000000000001 \
    9E670001 9E790020 D65F03C0

run_expect_x0 fcvtzu64_trunc_pos 3 \
    --set-reg x0=0x400F333333333333 \
    9E670001 9E790020 D65F03C0

# FCVTZS/FCVTZU 32-bit edges (S -> W)
run_expect_x0 fcvtzs32_pos_inf 2147483647 \
    --set-reg x0=0x7F800000 \
    1E270001 1E380020 D65F03C0

run_expect_x0 fcvtzs32_neg_inf 2147483648 \
    --set-reg x0=0xFF800000 \
    1E270001 1E380020 D65F03C0

run_expect_x0 fcvtzs32_subnormal 0 \
    --set-reg x0=0x00000001 \
    1E270001 1E380020 D65F03C0

run_expect_x0 fcvtzu32_nan 0 \
    --set-reg x0=0x7FC00000 \
    1E270001 1E390020 D65F03C0

run_expect_x0 fcvtzu32_neg_to_zero 0 \
    --set-reg x0=0xC079999A \
    1E270001 1E390020 D65F03C0

run_expect_x0 fcvtzu32_ge_2p32 4294967295 \
    --set-reg x0=0x4F800000 \
    1E270001 1E390020 D65F03C0

run_expect_x0 fcvtzu32_subnormal 0 \
    --set-reg x0=0x00000001 \
    1E270001 1E390020 D65F03C0

run_expect_x0 fcvtzu32_trunc_pos 3 \
    --set-reg x0=0x4079999A \
    1E270001 1E390020 D65F03C0

echo "FP conversion edge checks passed: $pass_count cases"
