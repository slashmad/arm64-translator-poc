#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "tiny_dbt_runtime.h"

int main(void) {
    /* Same stream as run-br-midblock-example, encoded as AArch64 little-endian bytes. */
    const uint8_t insn_bytes[] = {
        0x81, 0x01, 0x80, 0xD2, 0x20, 0x00, 0x1F, 0xD6, 0x00, 0x00, 0x80, 0xD2,
        0x40, 0x05, 0x80, 0xD2, 0x00, 0x04, 0x00, 0x91, 0xC0, 0x03, 0x5F, 0xD6,
    };

    TinyDbt *dbt = tiny_dbt_create_from_bytes(insn_bytes, sizeof(insn_bytes));
    if (!dbt) {
        fprintf(stderr, "create failed: %s\n", tiny_dbt_last_error(NULL));
        return 1;
    }

    uint64_t x0 = 0;
    TinyDbtRunOptions run_opts = {0};
    TinyDbtCpuState state;
    tiny_dbt_state_init(&state);
    state.pc = 0;
    if (!tiny_dbt_run_with_state(dbt, &state, &run_opts, &x0)) {
        fprintf(stderr, "run #1 failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }
    printf("run #1 x0 = %" PRIu64 " (0x%" PRIx64 ")\n", x0, x0);

    if (!tiny_dbt_invalidate_pc_indexes(dbt, "3")) {
        fprintf(stderr, "invalidate-pc-indexes failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }
    state.pc = 0;
    if (!tiny_dbt_run_with_state(dbt, &state, &run_opts, &x0)) {
        fprintf(stderr, "run #2 failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }
    printf("run #2 x0 = %" PRIu64 " (0x%" PRIx64 ")\n", x0, x0);

    run_opts.invalidate_dispatch = true;
    run_opts.max_retries = 8;
    state.pc = 0;
    if (!tiny_dbt_run_with_state(dbt, &state, &run_opts, &x0)) {
        fprintf(stderr, "run #3 failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }
    printf("run #3 x0 = %" PRIu64 " (0x%" PRIx64 ")\n", x0, x0);

    tiny_dbt_destroy(dbt);

    /* Memory API demo: preload guest memory and read it via translated code. */
    const uint32_t mem_load_insns[] = {
        0xD2800401u, /* movz x1, #0x20 */
        0xF9400020u, /* ldr x0, [x1] */
        0xD65F03C0u, /* ret */
    };
    dbt = tiny_dbt_create(mem_load_insns, sizeof(mem_load_insns) / sizeof(mem_load_insns[0]));
    if (!dbt) {
        fprintf(stderr, "create(memory) failed: %s\n", tiny_dbt_last_error(NULL));
        return 1;
    }

    const uint64_t expected = 0x1122334455667788ull;
    if (!tiny_dbt_guest_mem_write(dbt, 0x20u, &expected, sizeof(expected))) {
        fprintf(stderr, "guest_mem_write failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }

    uint64_t roundtrip = 0;
    if (!tiny_dbt_guest_mem_read(dbt, 0x20u, &roundtrip, sizeof(roundtrip))) {
        fprintf(stderr, "guest_mem_read failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }
    printf("mem roundtrip = 0x%" PRIx64 " (size=%zu)\n", roundtrip, tiny_dbt_guest_mem_size());

    tiny_dbt_state_init(&state);
    state.pc = 0;
    if (!tiny_dbt_run_with_state(dbt, &state, NULL, &x0)) {
        fprintf(stderr, "run #4 failed: %s\n", tiny_dbt_last_error(dbt));
        tiny_dbt_destroy(dbt);
        return 1;
    }
    printf("run #4 x0 = %" PRIu64 " (0x%" PRIx64 ")\n", x0, x0);

    tiny_dbt_destroy(dbt);
    return 0;
}
