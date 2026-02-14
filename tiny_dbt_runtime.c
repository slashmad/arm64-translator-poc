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
    uint64_t heap_base;
    uint64_t heap_brk;
    uint64_t heap_last_ptr;
    uint64_t heap_last_size;
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

enum {
    IMPORT_CB_RET_X0 = 0x10,
    IMPORT_CB_RET_X1 = 0x11,
    IMPORT_CB_RET_X2 = 0x12,
    IMPORT_CB_RET_X3 = 0x13,
    IMPORT_CB_RET_X4 = 0x14,
    IMPORT_CB_RET_X5 = 0x15,
    IMPORT_CB_RET_X6 = 0x16,
    IMPORT_CB_RET_X7 = 0x17,
    IMPORT_CB_ADD_X0_X1 = 0x20,
    IMPORT_CB_SUB_X0_X1 = 0x21,
    IMPORT_CB_RET_SP = 0x30,
    IMPORT_CB_NONNULL_X0 = 0x40,
    IMPORT_CB_GUEST_ALLOC_X0 = 0x50,
    IMPORT_CB_GUEST_FREE_X0 = 0x51,
    IMPORT_CB_GUEST_CALLOC_X0_X1 = 0x52,
    IMPORT_CB_GUEST_REALLOC_X0_X1 = 0x53,
    IMPORT_CB_GUEST_MEMCPY_X0_X1_X2 = 0x54,
    IMPORT_CB_GUEST_MEMSET_X0_X1_X2 = 0x55,
    IMPORT_CB_GUEST_MEMCMP_X0_X1_X2 = 0x56,
    IMPORT_CB_GUEST_MEMMOVE_X0_X1_X2 = 0x57,
    IMPORT_CB_GUEST_STRNLEN_X0_X1 = 0x58,
    IMPORT_CB_GUEST_STRLEN_X0 = 0x59,
    IMPORT_CB_GUEST_STRCMP_X0_X1 = 0x5A,
    IMPORT_CB_GUEST_STRNCMP_X0_X1_X2 = 0x5B,
    IMPORT_CB_GUEST_STRCPY_X0_X1 = 0x5C,
    IMPORT_CB_GUEST_STRNCPY_X0_X1_X2 = 0x5D,
    IMPORT_CB_GUEST_STRCHR_X0_X1 = 0x5E
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
static uint64_t dbt_runtime_import_callback_dispatch(CPUState *state, uint64_t callback_id);
static bool guest_heap_alloc(CPUState *state, uint64_t req, uint64_t *out_ptr, uint64_t *out_size);
static bool guest_heap_realloc_last(CPUState *state, uint64_t ptr, uint64_t req, uint64_t *out_ptr);
static bool guest_mem_range_valid(uint64_t addr, uint64_t len);
static int64_t guest_strcmp_impl(const uint8_t *mem, uint64_t a_addr, uint64_t b_addr, uint64_t limit, bool bounded);
static uint64_t guest_strnlen_scan(const uint8_t *mem, uint64_t addr, uint64_t max_len, bool *out_terminated);

/*
 * Current runtime guest memory pointer used by host import callbacks.
 * Thread-local keeps nested/parallel runtimes isolated.
 */
static _Thread_local uint8_t *g_tiny_dbt_current_guest_mem = NULL;

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

static bool guest_heap_alloc(CPUState *state, uint64_t req, uint64_t *out_ptr, uint64_t *out_size) {
    uint64_t base = 0;
    uint64_t brk = 0;
    uint64_t size = 0;
    uint64_t ptr = 0;

    if (!state || !out_ptr || !out_size) {
        return false;
    }
    if (req == 0) {
        return false;
    }
    if (req > UINT64_MAX - 15u) {
        return false;
    }

    base = state->heap_base ? state->heap_base : 0x1000u;
    if (base >= (uint64_t)GUEST_MEM_SIZE) {
        return false;
    }

    brk = state->heap_brk;
    if (brk < base) {
        brk = base;
    }

    size = (req + 15u) & ~15ull; /* 16-byte alignment */
    if (size == 0) {
        return false;
    }
    if (brk > (uint64_t)GUEST_MEM_SIZE || size > (uint64_t)GUEST_MEM_SIZE - brk) {
        return false;
    }

    ptr = brk;
    brk += size;
    state->heap_base = base;
    state->heap_brk = brk;
    state->heap_last_ptr = ptr;
    state->heap_last_size = size;
    *out_ptr = ptr;
    *out_size = size;
    return true;
}

static bool guest_heap_realloc_last(CPUState *state, uint64_t ptr, uint64_t req, uint64_t *out_ptr) {
    uint64_t size = 0;
    uint64_t old_size = 0;
    uint64_t brk = 0;
    uint64_t new_brk = 0;

    if (!state || !out_ptr) {
        return false;
    }
    if (ptr == 0 || req == 0) {
        return false;
    }
    if (ptr != state->heap_last_ptr || state->heap_last_size == 0) {
        return false;
    }

    old_size = state->heap_last_size;
    brk = state->heap_brk;
    if (old_size > UINT64_MAX - ptr || ptr + old_size != brk) {
        return false;
    }
    if (req > UINT64_MAX - 15u) {
        return false;
    }
    size = (req + 15u) & ~15ull; /* 16-byte alignment */
    if (size == 0) {
        return false;
    }
    if (ptr > UINT64_MAX - size) {
        return false;
    }
    new_brk = ptr + size;
    if (new_brk > (uint64_t)GUEST_MEM_SIZE) {
        return false;
    }

    state->heap_brk = new_brk;
    state->heap_last_size = size;
    *out_ptr = ptr;
    return true;
}

static bool guest_mem_range_valid(uint64_t addr, uint64_t len) {
    if (addr > (uint64_t)GUEST_MEM_SIZE || len > (uint64_t)GUEST_MEM_SIZE) {
        return false;
    }
    return addr <= (uint64_t)GUEST_MEM_SIZE - len;
}

static int64_t guest_strcmp_impl(const uint8_t *mem, uint64_t a_addr, uint64_t b_addr, uint64_t limit, bool bounded) {
    uint64_t i = 0;

    if (!mem || a_addr >= (uint64_t)GUEST_MEM_SIZE || b_addr >= (uint64_t)GUEST_MEM_SIZE) {
        return 0;
    }

    while (true) {
        uint64_t a_idx = a_addr + i;
        uint64_t b_idx = b_addr + i;
        uint8_t a_ch = 0;
        uint8_t b_ch = 0;

        if (bounded && i >= limit) {
            return 0;
        }
        if (a_idx >= (uint64_t)GUEST_MEM_SIZE || b_idx >= (uint64_t)GUEST_MEM_SIZE) {
            return 0;
        }

        a_ch = mem[(size_t)a_idx];
        b_ch = mem[(size_t)b_idx];
        if (a_ch != b_ch) {
            return (int64_t)((int)a_ch - (int)b_ch);
        }
        if (a_ch == 0) {
            return 0;
        }
        i++;
    }
}

static uint64_t guest_strnlen_scan(const uint8_t *mem, uint64_t addr, uint64_t max_len, bool *out_terminated) {
    uint64_t i = 0;
    if (out_terminated) {
        *out_terminated = false;
    }
    if (!mem || addr >= (uint64_t)GUEST_MEM_SIZE) {
        return 0;
    }
    for (i = 0; i < max_len; ++i) {
        uint64_t idx = addr + i;
        if (idx >= (uint64_t)GUEST_MEM_SIZE) {
            return i;
        }
        if (mem[(size_t)idx] == 0) {
            if (out_terminated) {
                *out_terminated = true;
            }
            return i;
        }
    }
    return max_len;
}

static uint64_t dbt_runtime_import_callback_dispatch(CPUState *state, uint64_t callback_id) {
    if (!state) {
        return 0;
    }

    switch (callback_id) {
        case IMPORT_CB_RET_X0:
            return state->x[0];
        case IMPORT_CB_RET_X1:
            return state->x[1];
        case IMPORT_CB_RET_X2:
            return state->x[2];
        case IMPORT_CB_RET_X3:
            return state->x[3];
        case IMPORT_CB_RET_X4:
            return state->x[4];
        case IMPORT_CB_RET_X5:
            return state->x[5];
        case IMPORT_CB_RET_X6:
            return state->x[6];
        case IMPORT_CB_RET_X7:
            return state->x[7];
        case IMPORT_CB_ADD_X0_X1:
            return state->x[0] + state->x[1];
        case IMPORT_CB_SUB_X0_X1:
            return state->x[0] - state->x[1];
        case IMPORT_CB_RET_SP:
            return state->sp;
        case IMPORT_CB_NONNULL_X0:
            return state->x[0] != 0 ? 1u : 0u;
        case IMPORT_CB_GUEST_ALLOC_X0: {
            uint64_t ptr = 0;
            uint64_t size = 0;
            if (!guest_heap_alloc(state, state->x[0], &ptr, &size)) {
                return 0;
            }
            return ptr;
        }
        case IMPORT_CB_GUEST_FREE_X0: {
            uint64_t ptr = state->x[0];
            if (ptr == 0) {
                return 0;
            }
            if (ptr == state->heap_last_ptr && state->heap_last_size != 0 &&
                state->heap_last_ptr + state->heap_last_size == state->heap_brk) {
                state->heap_brk = state->heap_last_ptr;
                state->heap_last_ptr = 0;
                state->heap_last_size = 0;
                return 1;
            }
            return 0;
        }
        case IMPORT_CB_GUEST_CALLOC_X0_X1: {
            uint64_t count = state->x[0];
            uint64_t elem = state->x[1];
            uint64_t req = 0;
            uint64_t ptr = 0;
            uint64_t size = 0;

            if (count == 0 || elem == 0) {
                return 0;
            }
            if (count > UINT64_MAX / elem) {
                return 0;
            }
            req = count * elem;
            if (!guest_heap_alloc(state, req, &ptr, &size)) {
                return 0;
            }

            if (g_tiny_dbt_current_guest_mem && ptr <= (uint64_t)GUEST_MEM_SIZE &&
                size <= (uint64_t)GUEST_MEM_SIZE - ptr) {
                memset(g_tiny_dbt_current_guest_mem + (size_t)ptr, 0, (size_t)size);
            }
            return ptr;
        }
        case IMPORT_CB_GUEST_REALLOC_X0_X1: {
            uint64_t ptr = state->x[0];
            uint64_t req = state->x[1];
            uint64_t out = 0;

            if (ptr == 0) {
                uint64_t size = 0;
                if (!guest_heap_alloc(state, req, &out, &size)) {
                    return 0;
                }
                return out;
            }
            if (req == 0) {
                if (ptr == state->heap_last_ptr && state->heap_last_size != 0 &&
                    state->heap_last_ptr + state->heap_last_size == state->heap_brk) {
                    state->heap_brk = state->heap_last_ptr;
                    state->heap_last_ptr = 0;
                    state->heap_last_size = 0;
                }
                return 0;
            }
            if (!guest_heap_realloc_last(state, ptr, req, &out)) {
                return 0;
            }
            return out;
        }
        case IMPORT_CB_GUEST_MEMCPY_X0_X1_X2: {
            uint64_t dst = state->x[0];
            uint64_t src = state->x[1];
            uint64_t len = state->x[2];

            if (len == 0) {
                return dst;
            }
            if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(dst, len) || !guest_mem_range_valid(src, len)) {
                return 0;
            }
            memmove(g_tiny_dbt_current_guest_mem + (size_t)dst, g_tiny_dbt_current_guest_mem + (size_t)src, (size_t)len);
            return dst;
        }
        case IMPORT_CB_GUEST_MEMSET_X0_X1_X2: {
            uint64_t dst = state->x[0];
            uint8_t value = (uint8_t)(state->x[1] & 0xFFu);
            uint64_t len = state->x[2];

            if (len == 0) {
                return dst;
            }
            if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(dst, len)) {
                return 0;
            }
            memset(g_tiny_dbt_current_guest_mem + (size_t)dst, value, (size_t)len);
            return dst;
        }
        case IMPORT_CB_GUEST_MEMCMP_X0_X1_X2: {
            uint64_t a_addr = state->x[0];
            uint64_t b_addr = state->x[1];
            uint64_t len = state->x[2];

            if (len == 0) {
                return 0;
            }
            if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(a_addr, len) ||
                !guest_mem_range_valid(b_addr, len)) {
                return 0;
            }

            const uint8_t *a = g_tiny_dbt_current_guest_mem + (size_t)a_addr;
            const uint8_t *b = g_tiny_dbt_current_guest_mem + (size_t)b_addr;
            for (uint64_t i = 0; i < len; ++i) {
                if (a[i] != b[i]) {
                    int64_t diff = (int64_t)((int)a[i] - (int)b[i]);
                    return (uint64_t)diff;
                }
            }
            return 0;
        }
        case IMPORT_CB_GUEST_MEMMOVE_X0_X1_X2: {
            uint64_t dst = state->x[0];
            uint64_t src = state->x[1];
            uint64_t len = state->x[2];

            if (len == 0) {
                return dst;
            }
            if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(dst, len) || !guest_mem_range_valid(src, len)) {
                return 0;
            }
            memmove(g_tiny_dbt_current_guest_mem + (size_t)dst, g_tiny_dbt_current_guest_mem + (size_t)src, (size_t)len);
            return dst;
        }
        case IMPORT_CB_GUEST_STRNLEN_X0_X1: {
            uint64_t addr = state->x[0];
            uint64_t max_len = state->x[1];

            if (!g_tiny_dbt_current_guest_mem || addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }

            uint64_t avail = (uint64_t)GUEST_MEM_SIZE - addr;
            uint64_t scan_len = max_len < avail ? max_len : avail;
            const uint8_t *s = g_tiny_dbt_current_guest_mem + (size_t)addr;
            for (uint64_t i = 0; i < scan_len; ++i) {
                if (s[i] == 0) {
                    return i;
                }
            }
            return scan_len;
        }
        case IMPORT_CB_GUEST_STRLEN_X0: {
            uint64_t addr = state->x[0];
            uint64_t max_len = 0;
            const uint8_t *s = NULL;

            if (!g_tiny_dbt_current_guest_mem || addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }
            max_len = (uint64_t)GUEST_MEM_SIZE - addr;
            s = g_tiny_dbt_current_guest_mem + (size_t)addr;
            for (uint64_t i = 0; i < max_len; ++i) {
                if (s[i] == 0) {
                    return i;
                }
            }
            return max_len;
        }
        case IMPORT_CB_GUEST_STRCMP_X0_X1: {
            int64_t diff = guest_strcmp_impl(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], 0, false);
            return (uint64_t)diff;
        }
        case IMPORT_CB_GUEST_STRNCMP_X0_X1_X2: {
            int64_t diff =
                guest_strcmp_impl(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], state->x[2], true);
            return (uint64_t)diff;
        }
        case IMPORT_CB_GUEST_STRCPY_X0_X1: {
            uint64_t dst = state->x[0];
            uint64_t src = state->x[1];
            bool terminated = false;
            uint64_t len = 0;
            uint64_t nbytes = 0;

            if (!g_tiny_dbt_current_guest_mem || dst >= (uint64_t)GUEST_MEM_SIZE || src >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }

            len = guest_strnlen_scan(g_tiny_dbt_current_guest_mem, src, (uint64_t)GUEST_MEM_SIZE - src, &terminated);
            if (!terminated) {
                return 0;
            }
            nbytes = len + 1; /* include trailing NUL */
            if (!guest_mem_range_valid(dst, nbytes) || !guest_mem_range_valid(src, nbytes)) {
                return 0;
            }

            memmove(g_tiny_dbt_current_guest_mem + (size_t)dst, g_tiny_dbt_current_guest_mem + (size_t)src, (size_t)nbytes);
            return dst;
        }
        case IMPORT_CB_GUEST_STRNCPY_X0_X1_X2: {
            uint64_t dst = state->x[0];
            uint64_t src = state->x[1];
            uint64_t n = state->x[2];
            uint64_t i = 0;
            bool saw_nul = false;

            if (!g_tiny_dbt_current_guest_mem || dst >= (uint64_t)GUEST_MEM_SIZE || src >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }
            if (n == 0) {
                return dst;
            }
            if (!guest_mem_range_valid(dst, n)) {
                return 0;
            }

            for (i = 0; i < n; ++i) {
                uint64_t src_idx = src + i;
                uint8_t ch = 0;
                if (!saw_nul) {
                    if (src_idx >= (uint64_t)GUEST_MEM_SIZE) {
                        return 0;
                    }
                    ch = g_tiny_dbt_current_guest_mem[(size_t)src_idx];
                    if (ch == 0) {
                        saw_nul = true;
                    }
                }
                g_tiny_dbt_current_guest_mem[(size_t)(dst + i)] = saw_nul ? 0 : ch;
            }
            return dst;
        }
        case IMPORT_CB_GUEST_STRCHR_X0_X1: {
            uint64_t addr = state->x[0];
            uint8_t needle = (uint8_t)(state->x[1] & 0xFFu);
            uint64_t i = 0;

            if (!g_tiny_dbt_current_guest_mem || addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }
            for (i = 0; addr + i < (uint64_t)GUEST_MEM_SIZE; ++i) {
                uint8_t ch = g_tiny_dbt_current_guest_mem[(size_t)(addr + i)];
                if (ch == needle) {
                    return addr + i;
                }
                if (ch == 0) {
                    break;
                }
            }
            return 0;
        }
        default:
            return 0;
    }
}
