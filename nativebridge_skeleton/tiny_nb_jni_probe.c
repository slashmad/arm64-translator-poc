#include "../tiny_dbt_runtime.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    /*
     * Minimal JNI-style probe:
     * - Code block is just RET.
     * - X0 is preloaded with JNI_VERSION_1_6.
     * - If runtime plumbing is healthy, RET returns that value unchanged.
     */
    const uint32_t code[] = {
        0xD65F03C0u, /* RET */
    };
    const uint64_t expected = 0x00010006u; /* JNI_VERSION_1_6 */

    TinyDbt *dbt = tiny_dbt_create(code, sizeof(code) / sizeof(code[0]));
    if (!dbt) {
        fprintf(stderr, "tiny_dbt_create failed\n");
        return 1;
    }

    TinyDbtCpuState state;
    tiny_dbt_state_init(&state);
    state.x[0] = expected;

    uint64_t out_x0 = 0;
    bool ok = tiny_dbt_run_with_state(dbt, &state, NULL, &out_x0);
    tiny_dbt_destroy(dbt);
    if (!ok) {
        fprintf(stderr, "tiny_dbt_run_with_state failed\n");
        return 1;
    }

    printf("JNI probe x0=%" PRIu64 " (0x%" PRIx64 ")\n", out_x0, out_x0);
    if (out_x0 != expected) {
        fprintf(stderr, "unexpected JNI probe value\n");
        return 1;
    }
    return 0;
}
