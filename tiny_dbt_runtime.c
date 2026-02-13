#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "tiny_dbt_runtime.h"

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} CodeBuf;

enum {
    GUEST_MEM_SIZE = 64 * 1024,
    LR_STACK_DEPTH = 64,
    LR_STACK_MAX_BYTES = LR_STACK_DEPTH * 8,
    DISPATCH_VERSION_INITIAL = 1,
    EXIT_REASON_NONE = 0,
    EXIT_REASON_OOB = 1,
    EXIT_REASON_VERSION_MISS = 2,
    EXIT_REASON_UNSUPPORTED = 3
};

typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint32_t nzcv;
    uint32_t _pad;
    uint64_t rflags;
    uint64_t dispatch_version;
    uint64_t exit_reason;
    uint64_t version_miss_pc_index;
    uint64_t lr_stack[LR_STACK_DEPTH];
    uint64_t lr_sp_bytes;
    uint64_t ret_ic_key;
    uint64_t ret_ic_target;
    uint64_t ret_ic_version;
    uint64_t excl_addr;
    uint64_t excl_size;
    uint64_t excl_valid;
    uint64_t v[32][2];
    uint64_t unsupported_pc_index;
    uint32_t unsupported_insn;
    uint32_t unsupported_pad;
} CPUState;

_Static_assert(sizeof(TinyDbtCpuState) == sizeof(CPUState), "TinyDbtCpuState layout drift");
_Static_assert(offsetof(TinyDbtCpuState, x) == offsetof(CPUState, x), "TinyDbtCpuState.x offset drift");
_Static_assert(offsetof(TinyDbtCpuState, pc) == offsetof(CPUState, pc), "TinyDbtCpuState.pc offset drift");
_Static_assert(offsetof(TinyDbtCpuState, dispatch_version) == offsetof(CPUState, dispatch_version),
               "TinyDbtCpuState.dispatch_version offset drift");
_Static_assert(offsetof(TinyDbtCpuState, ret_ic_target) == offsetof(CPUState, ret_ic_target),
               "TinyDbtCpuState.ret_ic_target offset drift");

enum {
    TINY_DBT_ERROR_CAP = 256
};

struct TinyDbt {
    size_t n_insn;
    size_t cap;
    uint8_t *mem;
    uint8_t *guest_mem;
    uint64_t *entry_targets;
    uint64_t *entry_versions;
    uint64_t dispatch_version;
    char last_error[TINY_DBT_ERROR_CAP];
};

typedef struct {
    size_t imm32_off;
    int target_pc;
} Patch;

typedef struct {
    Patch *items;
    size_t len;
    size_t cap;
} PatchVec;

typedef struct {
    size_t imm32_off;
    uint64_t fault_pc_bytes;
} OobPatch;

typedef struct {
    OobPatch *items;
    size_t len;
    size_t cap;
} OobPatchVec;

typedef struct {
    size_t imm32_off;
    uint64_t fault_pc_bytes;
    uint32_t insn;
} UnsupportedPatch;

typedef struct {
    UnsupportedPatch *items;
    size_t len;
    size_t cap;
} UnsupportedPatchVec;

typedef struct {
    size_t *items;
    size_t len;
    size_t cap;
} OffPatchVec;

static void patch_rel32_at(uint8_t *out, size_t imm_off, size_t target_off);
static void emit_preserve_guest_flags_begin(CodeBuf *cb);
static void emit_preserve_guest_flags_end(CodeBuf *cb);

static void tiny_dbt_set_error(TinyDbt *dbt, const char *fmt, ...) {
    if (!dbt) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dbt->last_error, sizeof(dbt->last_error), fmt, ap);
    va_end(ap);
}


#include "tiny_dbt_runtime_emit.inc.c"
#include "tiny_dbt_runtime_helpers.inc.c"
#include "tiny_dbt_runtime_decode.inc.c"
#include "tiny_dbt_runtime_api.inc.c"
