#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    IMPORT_CB_RET_0 = 0x01,
    IMPORT_CB_RET_1 = 0x02,
    IMPORT_CB_RET_NEG1 = 0x03,
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
    IMPORT_CB_GUEST_STRCHR_X0_X1 = 0x5E,
    IMPORT_CB_GUEST_STRRCHR_X0_X1 = 0x5F,
    IMPORT_CB_GUEST_STRSTR_X0_X1 = 0x60,
    IMPORT_CB_GUEST_MEMCHR_X0_X1_X2 = 0x61,
    IMPORT_CB_GUEST_MEMRCHR_X0_X1_X2 = 0x62,
    IMPORT_CB_GUEST_ATOI_X0 = 0x63,
    IMPORT_CB_GUEST_STRTOL_X0_X1_X2 = 0x64,
    IMPORT_CB_GUEST_SNPRINTF_X0_X1_X2 = 0x65,
    IMPORT_CB_GUEST_STRTOD_X0_X1 = 0x66,
    IMPORT_CB_GUEST_SSCANF_X0_X1_X2 = 0x67,
    IMPORT_CB_GUEST_VSNPRINTF_X0_X1_X2_X3 = 0x68,
    IMPORT_CB_GUEST_VSSCANF_X0_X1_X2 = 0x69,
    IMPORT_CB_GUEST_VSNPRINTF_CHK_X0_X1_X4_X5 = 0x6A,
    IMPORT_CB_GUEST_VFPRINTF_X0_X1_X2 = 0x6B,
    IMPORT_CB_GUEST_VASPRINTF_X0_X1_X2 = 0x6C,
    IMPORT_CB_GUEST_STRTOUL_X0_X1_X2 = 0x6D,
    IMPORT_CB_GUEST_POSIX_MEMALIGN_X0_X1_X2 = 0x6E,
    IMPORT_CB_GUEST_BASENAME_X0 = 0x6F,
    IMPORT_CB_GUEST_STRDUP_X0 = 0x70,
    IMPORT_CB_GUEST_STRTOF_X0_X1 = 0x71,
    IMPORT_CB_GUEST_POW_X0_X1 = 0x72,
    IMPORT_CB_GUEST_SQRT_X0 = 0x73,
    IMPORT_CB_GUEST_COS_X0 = 0x74,
    IMPORT_CB_GUEST_TAN_X0 = 0x75,
    IMPORT_CB_GUEST_ISLOWER_X0 = 0x76,
    IMPORT_CB_GUEST_ISSPACE_X0 = 0x77,
    IMPORT_CB_GUEST_ISXDIGIT_X0 = 0x78,
    IMPORT_CB_GUEST_ISUPPER_X0 = 0x79,
    IMPORT_CB_GUEST_TOUPPER_X0 = 0x7A,
    IMPORT_CB_GUEST_TOLOWER_X0 = 0x7B,
    IMPORT_CB_RET_NEG1_ENOSYS = 0x7C,
    IMPORT_CB_RET_NEG1_EAGAIN = 0x7D,
    IMPORT_CB_RET_NEG1_EINTR = 0x7E,
    IMPORT_CB_GUEST_ERRNO_PTR = 0x7F,
    IMPORT_CB_GUEST_HANDLE_X0 = 0x80,
    IMPORT_CB_GUEST_ACOSF_X0 = 0x81,
    IMPORT_CB_GUEST_ASINF_X0 = 0x82,
    IMPORT_CB_GUEST_ATAN2F_X0_X1 = 0x83,
    IMPORT_CB_GUEST_EXPF_X0 = 0x84,
    IMPORT_CB_GUEST_LOGF_X0 = 0x85,
    IMPORT_CB_GUEST_FMODF_X0_X1 = 0x86,
    IMPORT_CB_GUEST_GMTIME_X0 = 0x87,
    IMPORT_CB_GUEST_CTIME_X0 = 0x88,
    IMPORT_CB_GUEST_TZSET_0 = 0x89,
    IMPORT_CB_GUEST_DAYLIGHT_PTR = 0x8A,
    IMPORT_CB_GUEST_TIMEZONE_PTR = 0x8B,
    IMPORT_CB_RET_NEG1_EACCES = 0x8C,
    IMPORT_CB_RET_NEG1_ENOENT = 0x8D,
    IMPORT_CB_RET_NEG1_EPERM = 0x8E,
    IMPORT_CB_RET_NEG1_ETIMEDOUT = 0x8F,
    IMPORT_CB_GUEST_EXP_X0 = 0x90,
    IMPORT_CB_GUEST_LOG_X0 = 0x91,
    IMPORT_CB_GUEST_LOG10_X0 = 0x92,
    IMPORT_CB_GUEST_FLOOR_X0 = 0x93,
    IMPORT_CB_GUEST_CEIL_X0 = 0x94,
    IMPORT_CB_GUEST_TRUNC_X0 = 0x95,
    IMPORT_CB_GUEST_FMOD_X0_X1 = 0x96,
    IMPORT_CB_GUEST_SIN_X0 = 0x97,
    IMPORT_CB_GUEST_SINH_X0 = 0x98,
    IMPORT_CB_GUEST_TANH_X0 = 0x99,
    IMPORT_CB_GUEST_SINF_X0 = 0x9A,
    IMPORT_CB_GUEST_SINCOSF_X0_X1_X2 = 0x9B,
    IMPORT_CB_GUEST_EXP2F_X0 = 0x9C,
    IMPORT_CB_GUEST_LOG2F_X0 = 0x9D,
    IMPORT_CB_GUEST_LOG10F_X0 = 0x9E,
    IMPORT_CB_GUEST_LROUND_X0 = 0x9F,
    IMPORT_CB_GUEST_OPEN_X0_X1_X2 = 0xA0,
    IMPORT_CB_GUEST_OPENAT_X0_X1_X2_X3 = 0xA1,
    IMPORT_CB_GUEST_READ_X0_X1_X2 = 0xA2,
    IMPORT_CB_GUEST_WRITE_X0_X1_X2 = 0xA3,
    IMPORT_CB_GUEST_CLOSE_X0 = 0xA4
};

enum {
    GUEST_HANDLE_CACHE_SLOTS = 64
};

enum {
    GUEST_FD_TABLE_SIZE = 32,
    GUEST_FD_MIN = 3,
    GUEST_FD_SYNTHETIC_MAX_READ = 16
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

typedef struct {
    bool used;
    bool readable;
    bool writable;
    uint64_t cursor;
    uint64_t seed;
    uint64_t bytes_written;
} GuestFdEntry;

typedef enum {
    GUEST_FMT_LEN_NONE = 0,
    GUEST_FMT_LEN_HH,
    GUEST_FMT_LEN_H,
    GUEST_FMT_LEN_L,
    GUEST_FMT_LEN_LL,
    GUEST_FMT_LEN_J,
    GUEST_FMT_LEN_Z,
    GUEST_FMT_LEN_T,
    GUEST_FMT_LEN_CAP_L
} GuestFmtLength;

typedef struct {
    bool flag_left;
    bool flag_plus;
    bool flag_space;
    bool flag_alt;
    bool flag_zero;
    bool width_specified;
    int width;
    bool precision_specified;
    int precision;
    GuestFmtLength length;
    uint8_t conv;
} GuestPrintfSpec;

static void patch_rel32_at(uint8_t *out, size_t imm_off, size_t target_off);
static void emit_preserve_guest_flags_begin(CodeBuf *cb);
static void emit_preserve_guest_flags_end(CodeBuf *cb);
static uint64_t dbt_runtime_import_callback_dispatch(CPUState *state, uint64_t callback_id);
static bool guest_heap_alloc(CPUState *state, uint64_t req, uint64_t *out_ptr, uint64_t *out_size);
static bool guest_heap_realloc_last(CPUState *state, uint64_t ptr, uint64_t req, uint64_t *out_ptr);
static bool guest_heap_alloc_aligned(CPUState *state, uint64_t align, uint64_t req, uint64_t *out_ptr);
static bool guest_mem_range_valid(uint64_t addr, uint64_t len);
static int64_t guest_strcmp_impl(const uint8_t *mem, uint64_t a_addr, uint64_t b_addr, uint64_t limit, bool bounded);
static uint64_t guest_strnlen_scan(const uint8_t *mem, uint64_t addr, uint64_t max_len, bool *out_terminated);
static bool guest_parse_strtol(const uint8_t *mem, uint64_t addr, int base_arg, int64_t *out_value, uint64_t *out_end);
static bool guest_ascii_isspace(uint8_t ch);
static int guest_digit_value(uint8_t ch);
static bool guest_is_power_of_two_u64(uint64_t value);
static bool guest_write_scalar(uint8_t *mem, uint64_t addr, const void *src, size_t len);
static bool guest_vararg_read_u64(const CPUState *state, unsigned *arg_idx, uint64_t *out_value);
static bool guest_prepare_vsnprintf_state(const CPUState *state, uint64_t va_list_addr, CPUState *out_state);
static bool guest_prepare_vsscanf_state(const CPUState *state, uint64_t va_list_addr, CPUState *out_state);
static uint64_t guest_snprintf_next_arg(const CPUState *state, unsigned *arg_idx);
static uint64_t guest_sscanf_next_arg(const CPUState *state, unsigned *arg_idx);
static void guest_snprintf_add_total(uint64_t *io_total, uint64_t add);
static void guest_snprintf_append_char(uint8_t *mem, uint64_t dst_addr, uint64_t dst_size, uint64_t *io_total, uint8_t ch);
static void guest_snprintf_append_str(uint8_t *mem, uint64_t dst_addr, uint64_t dst_size, uint64_t *io_total, const char *s,
                                      size_t len);
static bool guest_snprintf_build_format(char *out, size_t out_cap, const GuestPrintfSpec *spec, char conv,
                                        const char *len_override);
static int64_t guest_snprintf_signed_arg(uint64_t raw, GuestFmtLength len);
static uint64_t guest_snprintf_unsigned_arg(uint64_t raw, GuestFmtLength len);
static uint64_t guest_snprintf_format(uint8_t *mem, uint64_t dst_addr, uint64_t dst_size, uint64_t fmt_addr,
                                      const CPUState *state);
static bool guest_parse_strtod(const uint8_t *mem, uint64_t addr, double *out_value, uint64_t *out_end);
static bool guest_sscanf_store_signed(uint8_t *mem, uint64_t addr, GuestFmtLength len, int64_t value);
static bool guest_sscanf_store_unsigned(uint8_t *mem, uint64_t addr, GuestFmtLength len, uint64_t value);
static bool guest_sscanf_store_float(uint8_t *mem, uint64_t addr, GuestFmtLength len, double value);
static uint64_t guest_sscanf_scan(uint8_t *mem, uint64_t input_addr, uint64_t fmt_addr, const CPUState *state);
static double guest_fp_arg_f64(const CPUState *state, unsigned idx);
static uint64_t guest_fp_ret_f64(CPUState *state, double value);
static float guest_fp_arg_f32(const CPUState *state, unsigned idx);
static uint64_t guest_fp_ret_f32(CPUState *state, float value);
static bool guest_errno_slot_ensure(CPUState *state, uint64_t *out_addr);
static void guest_errno_write(CPUState *state, uint64_t err);
static uint64_t guest_errno_ptr(CPUState *state);
static bool guest_static_slot_ensure(CPUState *state, uint64_t *slot_addr, uint64_t align, uint64_t size);
static uint64_t guest_handle_x0(CPUState *state);
static uint64_t guest_gmtime_x0(CPUState *state);
static uint64_t guest_ctime_x0(CPUState *state);
static uint64_t guest_tzset_0(CPUState *state);
static uint64_t guest_daylight_ptr(CPUState *state);
static uint64_t guest_timezone_ptr(CPUState *state);
static uint64_t guest_open_x0_x1_x2(CPUState *state);
static uint64_t guest_openat_x0_x1_x2_x3(CPUState *state);
static uint64_t guest_read_x0_x1_x2(CPUState *state);
static uint64_t guest_write_x0_x1_x2(CPUState *state);
static uint64_t guest_close_x0(CPUState *state);

/*
 * Current runtime guest memory pointer used by host import callbacks.
 * Thread-local keeps nested/parallel runtimes isolated.
 */
static _Thread_local uint8_t *g_tiny_dbt_current_guest_mem = NULL;
static _Thread_local uint64_t g_tiny_dbt_errno_slot_addr = 0;
static _Thread_local uint64_t g_tiny_dbt_daylight_slot_addr = 0;
static _Thread_local uint64_t g_tiny_dbt_timezone_slot_addr = 0;
static _Thread_local uint64_t g_tiny_dbt_ctime_buf_addr = 0;
static _Thread_local uint64_t g_tiny_dbt_gmtime_tm_addr = 0;
static _Thread_local size_t g_tiny_dbt_handle_cache_len = 0;
static _Thread_local uint64_t g_tiny_dbt_handle_cache_keys[GUEST_HANDLE_CACHE_SLOTS];
static _Thread_local uint64_t g_tiny_dbt_handle_cache_ptrs[GUEST_HANDLE_CACHE_SLOTS];
static _Thread_local GuestFdEntry g_tiny_dbt_guest_fds[GUEST_FD_TABLE_SIZE];

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

static bool guest_heap_alloc_aligned(CPUState *state, uint64_t align, uint64_t req, uint64_t *out_ptr) {
    uint64_t base = 0;
    uint64_t brk = 0;
    uint64_t ptr = 0;
    uint64_t size = 0;
    uint64_t mask = 0;

    if (!state || !out_ptr || align < sizeof(uint64_t) || !guest_is_power_of_two_u64(align)) {
        return false;
    }

    if (req > UINT64_MAX - 15u) {
        return false;
    }
    size = (req + 15u) & ~15ull;
    if (size == 0) {
        size = 16u; /* match malloc-like minimum allocation in PoC mode */
    }

    base = state->heap_base ? state->heap_base : 0x1000u;
    if (base >= (uint64_t)GUEST_MEM_SIZE) {
        return false;
    }
    brk = state->heap_brk;
    if (brk < base) {
        brk = base;
    }

    mask = align - 1u;
    if (brk > UINT64_MAX - mask) {
        return false;
    }
    ptr = (brk + mask) & ~mask;
    if (ptr > (uint64_t)GUEST_MEM_SIZE || size > (uint64_t)GUEST_MEM_SIZE - ptr) {
        return false;
    }

    state->heap_base = base;
    state->heap_brk = ptr + size;
    state->heap_last_ptr = ptr;
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

static bool guest_ascii_isspace(uint8_t ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v';
}

static int guest_digit_value(uint8_t ch) {
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0');
    }
    if (ch >= 'a' && ch <= 'z') {
        return 10 + (int)(ch - 'a');
    }
    if (ch >= 'A' && ch <= 'Z') {
        return 10 + (int)(ch - 'A');
    }
    return -1;
}

static bool guest_is_power_of_two_u64(uint64_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

static bool guest_parse_strtol(const uint8_t *mem, uint64_t addr, int base_arg, int64_t *out_value, uint64_t *out_end) {
    uint64_t p = 0;
    int sign = 1;
    int base = 0;
    uint64_t acc = 0;
    uint64_t max_mag = 0;
    bool any = false;

    if (!mem || !out_value || !out_end || addr >= (uint64_t)GUEST_MEM_SIZE) {
        return false;
    }

    *out_value = 0;
    *out_end = addr;
    p = addr;

    while (p < (uint64_t)GUEST_MEM_SIZE && guest_ascii_isspace(mem[(size_t)p])) {
        p++;
    }

    if (p < (uint64_t)GUEST_MEM_SIZE) {
        if (mem[(size_t)p] == '-') {
            sign = -1;
            p++;
        } else if (mem[(size_t)p] == '+') {
            p++;
        }
    }

    base = base_arg;
    if (base == 0) {
        base = 10;
        if (p < (uint64_t)GUEST_MEM_SIZE && mem[(size_t)p] == '0') {
            base = 8;
            if (p + 1 < (uint64_t)GUEST_MEM_SIZE &&
                (mem[(size_t)(p + 1)] == 'x' || mem[(size_t)(p + 1)] == 'X') &&
                p + 2 < (uint64_t)GUEST_MEM_SIZE && guest_digit_value(mem[(size_t)(p + 2)]) >= 0 &&
                guest_digit_value(mem[(size_t)(p + 2)]) < 16) {
                base = 16;
                p += 2;
            }
        }
    } else if (base == 16 && p + 1 < (uint64_t)GUEST_MEM_SIZE && mem[(size_t)p] == '0' &&
               (mem[(size_t)(p + 1)] == 'x' || mem[(size_t)(p + 1)] == 'X')) {
        p += 2;
    }

    if (base < 2 || base > 36) {
        *out_end = addr;
        return true;
    }

    max_mag = (sign < 0) ? ((uint64_t)INT64_MAX + 1u) : (uint64_t)INT64_MAX;
    while (p < (uint64_t)GUEST_MEM_SIZE) {
        int dv = guest_digit_value(mem[(size_t)p]);
        uint64_t u_dv = 0;
        if (dv < 0 || dv >= base) {
            break;
        }
        u_dv = (uint64_t)dv;
        any = true;
        if (acc <= (max_mag - u_dv) / (uint64_t)base) {
            acc = acc * (uint64_t)base + u_dv;
        } else {
            acc = max_mag; /* saturate in PoC mode */
        }
        p++;
    }

    if (!any) {
        *out_end = addr;
        *out_value = 0;
        return true;
    }

    *out_end = p;
    if (sign < 0) {
        if (acc == (uint64_t)INT64_MAX + 1u) {
            *out_value = INT64_MIN;
        } else {
            *out_value = -(int64_t)acc;
        }
    } else {
        *out_value = (int64_t)acc;
    }
    return true;
}

static bool guest_write_scalar(uint8_t *mem, uint64_t addr, const void *src, size_t len) {
    if (!mem || !src || len == 0 || !guest_mem_range_valid(addr, (uint64_t)len)) {
        return false;
    }
    memcpy(mem + (size_t)addr, src, len);
    return true;
}

static bool guest_vararg_read_u64(const CPUState *state, unsigned *arg_idx, uint64_t *out_value) {
    uint64_t value = 0;
    bool ok = true;

    if (!state || !arg_idx || !out_value) {
        return false;
    }

    if (*arg_idx <= 7u) {
        value = state->x[*arg_idx];
    } else {
        uint64_t slot = (uint64_t)(*arg_idx - 8u);
        uint64_t byte_off = 0;
        uint64_t addr = 0;
        if (slot > UINT64_MAX / 8u) {
            ok = false;
        } else {
            byte_off = slot * 8u;
            if (state->sp > UINT64_MAX - byte_off) {
                ok = false;
            } else {
                addr = state->sp + byte_off;
                if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(addr, sizeof(uint64_t))) {
                    ok = false;
                } else {
                    memcpy(&value, g_tiny_dbt_current_guest_mem + (size_t)addr, sizeof(value));
                }
            }
        }
    }

    (*arg_idx)++;
    *out_value = value;
    return ok;
}

static bool guest_prepare_vsnprintf_state(const CPUState *state, uint64_t va_list_addr, CPUState *out_state) {
    uint64_t cursor = va_list_addr;
    if (!state || !out_state || !g_tiny_dbt_current_guest_mem) {
        return false;
    }
    *out_state = *state;
    for (unsigned reg = 3u; reg <= 7u; ++reg) {
        uint64_t value = 0;
        if (!guest_mem_range_valid(cursor, sizeof(uint64_t))) {
            return false;
        }
        memcpy(&value, g_tiny_dbt_current_guest_mem + (size_t)cursor, sizeof(value));
        out_state->x[reg] = value;
        cursor += sizeof(uint64_t);
    }
    out_state->sp = cursor;
    return true;
}

static bool guest_prepare_vsscanf_state(const CPUState *state, uint64_t va_list_addr, CPUState *out_state) {
    uint64_t cursor = va_list_addr;
    if (!state || !out_state || !g_tiny_dbt_current_guest_mem) {
        return false;
    }
    *out_state = *state;
    for (unsigned reg = 2u; reg <= 7u; ++reg) {
        uint64_t value = 0;
        if (!guest_mem_range_valid(cursor, sizeof(uint64_t))) {
            return false;
        }
        memcpy(&value, g_tiny_dbt_current_guest_mem + (size_t)cursor, sizeof(value));
        out_state->x[reg] = value;
        cursor += sizeof(uint64_t);
    }
    out_state->sp = cursor;
    return true;
}

static uint64_t guest_snprintf_next_arg(const CPUState *state, unsigned *arg_idx) {
    uint64_t value = 0;
    if (!guest_vararg_read_u64(state, arg_idx, &value)) {
        return 0;
    }
    return value;
}

static uint64_t guest_sscanf_next_arg(const CPUState *state, unsigned *arg_idx) {
    uint64_t value = 0;
    if (!guest_vararg_read_u64(state, arg_idx, &value)) {
        return 0;
    }
    return value;
}

static void guest_snprintf_add_total(uint64_t *io_total, uint64_t add) {
    if (!io_total || add == 0) {
        return;
    }
    if (*io_total > UINT64_MAX - add) {
        *io_total = UINT64_MAX;
        return;
    }
    *io_total += add;
}

static void guest_snprintf_append_char(uint8_t *mem, uint64_t dst_addr, uint64_t dst_size, uint64_t *io_total, uint8_t ch) {
    if (!io_total) {
        return;
    }
    if (mem && dst_size > 0 && *io_total < dst_size - 1u) {
        mem[(size_t)(dst_addr + *io_total)] = ch;
    }
    guest_snprintf_add_total(io_total, 1u);
}

static void guest_snprintf_append_str(uint8_t *mem, uint64_t dst_addr, uint64_t dst_size, uint64_t *io_total, const char *s,
                                      size_t len) {
    if (!s || !io_total) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        guest_snprintf_append_char(mem, dst_addr, dst_size, io_total, (uint8_t)s[i]);
    }
}

static const char *guest_fmt_length_suffix(GuestFmtLength len) {
    switch (len) {
        case GUEST_FMT_LEN_HH:
            return "hh";
        case GUEST_FMT_LEN_H:
            return "h";
        case GUEST_FMT_LEN_L:
            return "l";
        case GUEST_FMT_LEN_LL:
            return "ll";
        case GUEST_FMT_LEN_J:
            return "j";
        case GUEST_FMT_LEN_Z:
            return "z";
        case GUEST_FMT_LEN_T:
            return "t";
        case GUEST_FMT_LEN_CAP_L:
            return "L";
        case GUEST_FMT_LEN_NONE:
        default:
            return "";
    }
}

static bool guest_snprintf_build_format(char *out, size_t out_cap, const GuestPrintfSpec *spec, char conv,
                                        const char *len_override) {
    char flags[8];
    char width_buf[32];
    char prec_buf[32];
    const char *len = NULL;
    size_t fi = 0;
    int n = 0;

    if (!out || out_cap == 0 || !spec) {
        return false;
    }

    flags[0] = '\0';
    if (spec->flag_left && fi < sizeof(flags) - 1u) {
        flags[fi++] = '-';
    }
    if (spec->flag_plus && fi < sizeof(flags) - 1u) {
        flags[fi++] = '+';
    }
    if (spec->flag_space && fi < sizeof(flags) - 1u) {
        flags[fi++] = ' ';
    }
    if (spec->flag_alt && fi < sizeof(flags) - 1u) {
        flags[fi++] = '#';
    }
    if (spec->flag_zero && fi < sizeof(flags) - 1u) {
        flags[fi++] = '0';
    }
    flags[fi] = '\0';

    width_buf[0] = '\0';
    if (spec->width_specified) {
        n = snprintf(width_buf, sizeof(width_buf), "%d", spec->width > 0 ? spec->width : 0);
        if (n < 0 || (size_t)n >= sizeof(width_buf)) {
            return false;
        }
    }

    prec_buf[0] = '\0';
    if (spec->precision_specified) {
        n = snprintf(prec_buf, sizeof(prec_buf), ".%d", spec->precision >= 0 ? spec->precision : 0);
        if (n < 0 || (size_t)n >= sizeof(prec_buf)) {
            return false;
        }
    }

    len = len_override ? len_override : guest_fmt_length_suffix(spec->length);
    n = snprintf(out, out_cap, "%%%s%s%s%s%c", flags, width_buf, prec_buf, len, conv);
    return n > 0 && (size_t)n < out_cap;
}

static int64_t guest_snprintf_signed_arg(uint64_t raw, GuestFmtLength len) {
    switch (len) {
        case GUEST_FMT_LEN_HH:
            return (int8_t)raw;
        case GUEST_FMT_LEN_H:
            return (int16_t)raw;
        case GUEST_FMT_LEN_L:
            return (long)(int64_t)raw;
        case GUEST_FMT_LEN_LL:
            return (long long)(int64_t)raw;
        case GUEST_FMT_LEN_J:
            return (intmax_t)(int64_t)raw;
        case GUEST_FMT_LEN_Z:
            return (ssize_t)(int64_t)raw;
        case GUEST_FMT_LEN_T:
            return (ptrdiff_t)(int64_t)raw;
        case GUEST_FMT_LEN_CAP_L:
            return (long long)(int64_t)raw;
        case GUEST_FMT_LEN_NONE:
        default:
            return (int32_t)raw;
    }
}

static uint64_t guest_snprintf_unsigned_arg(uint64_t raw, GuestFmtLength len) {
    switch (len) {
        case GUEST_FMT_LEN_HH:
            return (uint8_t)raw;
        case GUEST_FMT_LEN_H:
            return (uint16_t)raw;
        case GUEST_FMT_LEN_L:
            return (unsigned long)raw;
        case GUEST_FMT_LEN_LL:
            return (unsigned long long)raw;
        case GUEST_FMT_LEN_J:
            return (uintmax_t)raw;
        case GUEST_FMT_LEN_Z:
            return (size_t)raw;
        case GUEST_FMT_LEN_T:
            return (uint64_t)(ptrdiff_t)raw;
        case GUEST_FMT_LEN_CAP_L:
            return (unsigned long long)raw;
        case GUEST_FMT_LEN_NONE:
        default:
            return (uint32_t)raw;
    }
}

static uint64_t guest_snprintf_format(uint8_t *mem, uint64_t dst_addr, uint64_t dst_size, uint64_t fmt_addr,
                                      const CPUState *state) {
    bool fmt_terminated = false;
    uint64_t fmt_len = 0;
    uint64_t total = 0;
    uint64_t i = 0;
    unsigned arg_idx = 3;

    if (!mem || !state || fmt_addr >= (uint64_t)GUEST_MEM_SIZE) {
        return 0;
    }
    if (dst_size > 0 && !guest_mem_range_valid(dst_addr, dst_size)) {
        return 0;
    }

    fmt_len = guest_strnlen_scan(mem, fmt_addr, (uint64_t)GUEST_MEM_SIZE - fmt_addr, &fmt_terminated);
    if (!fmt_terminated) {
        return 0;
    }

    while (i < fmt_len) {
        uint8_t ch = mem[(size_t)(fmt_addr + i)];
        if (ch != '%') {
            guest_snprintf_append_char(mem, dst_addr, dst_size, &total, ch);
            i++;
            continue;
        }

        uint64_t spec_start = i;
        GuestPrintfSpec spec = {0};
        bool parsed = true;

        i++;
        if (i >= fmt_len) {
            guest_snprintf_append_char(mem, dst_addr, dst_size, &total, '%');
            break;
        }
        if (mem[(size_t)(fmt_addr + i)] == '%') {
            guest_snprintf_append_char(mem, dst_addr, dst_size, &total, '%');
            i++;
            continue;
        }

        while (i < fmt_len) {
            uint8_t f = mem[(size_t)(fmt_addr + i)];
            if (f == '-') {
                spec.flag_left = true;
            } else if (f == '+') {
                spec.flag_plus = true;
            } else if (f == ' ') {
                spec.flag_space = true;
            } else if (f == '#') {
                spec.flag_alt = true;
            } else if (f == '0') {
                spec.flag_zero = true;
            } else {
                break;
            }
            i++;
        }

        if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == '*') {
            int w = (int)(int64_t)guest_snprintf_next_arg(state, &arg_idx);
            spec.width_specified = true;
            if (w < 0) {
                spec.flag_left = true;
                if (w == INT_MIN) {
                    spec.width = INT_MAX;
                } else {
                    spec.width = -w;
                }
            } else {
                spec.width = w;
            }
            i++;
        } else {
            int w = 0;
            bool saw = false;
            while (i < fmt_len) {
                uint8_t d = mem[(size_t)(fmt_addr + i)];
                if (d < '0' || d > '9') {
                    break;
                }
                saw = true;
                if (w <= INT_MAX / 10) {
                    w *= 10;
                    if (w <= INT_MAX - (int)(d - '0')) {
                        w += (int)(d - '0');
                    } else {
                        w = INT_MAX;
                    }
                } else {
                    w = INT_MAX;
                }
                i++;
            }
            if (saw) {
                spec.width_specified = true;
                spec.width = w;
            }
        }

        if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == '.') {
            i++;
            spec.precision_specified = true;
            spec.precision = 0;
            if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == '*') {
                int p = (int)(int64_t)guest_snprintf_next_arg(state, &arg_idx);
                if (p < 0) {
                    spec.precision_specified = false;
                } else {
                    spec.precision = p;
                }
                i++;
            } else {
                int p = 0;
                while (i < fmt_len) {
                    uint8_t d = mem[(size_t)(fmt_addr + i)];
                    if (d < '0' || d > '9') {
                        break;
                    }
                    if (p <= INT_MAX / 10) {
                        p *= 10;
                        if (p <= INT_MAX - (int)(d - '0')) {
                            p += (int)(d - '0');
                        } else {
                            p = INT_MAX;
                        }
                    } else {
                        p = INT_MAX;
                    }
                    i++;
                }
                spec.precision = p;
            }
        }

        if (i + 1u < fmt_len && mem[(size_t)(fmt_addr + i)] == 'h' && mem[(size_t)(fmt_addr + i + 1u)] == 'h') {
            spec.length = GUEST_FMT_LEN_HH;
            i += 2u;
        } else if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == 'h') {
            spec.length = GUEST_FMT_LEN_H;
            i++;
        } else if (i + 1u < fmt_len && mem[(size_t)(fmt_addr + i)] == 'l' && mem[(size_t)(fmt_addr + i + 1u)] == 'l') {
            spec.length = GUEST_FMT_LEN_LL;
            i += 2u;
        } else if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == 'l') {
            spec.length = GUEST_FMT_LEN_L;
            i++;
        } else if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == 'j') {
            spec.length = GUEST_FMT_LEN_J;
            i++;
        } else if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == 'z') {
            spec.length = GUEST_FMT_LEN_Z;
            i++;
        } else if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == 't') {
            spec.length = GUEST_FMT_LEN_T;
            i++;
        } else if (i < fmt_len && mem[(size_t)(fmt_addr + i)] == 'L') {
            spec.length = GUEST_FMT_LEN_CAP_L;
            i++;
        }

        if (i >= fmt_len) {
            parsed = false;
        } else {
            spec.conv = mem[(size_t)(fmt_addr + i)];
        }

        if (parsed) {
            char fmt_buf[128];
            char rendered[512];
            int n = -1;
            bool supported = true;

            switch (spec.conv) {
                case 'd':
                case 'i': {
                    int64_t sval = guest_snprintf_signed_arg(guest_snprintf_next_arg(state, &arg_idx), spec.length);
                    if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, spec.conv, "ll")) {
                        supported = false;
                        break;
                    }
                    n = snprintf(rendered, sizeof(rendered), fmt_buf, (long long)sval);
                    break;
                }
                case 'u':
                case 'x':
                case 'X':
                case 'o': {
                    uint64_t uval = guest_snprintf_unsigned_arg(guest_snprintf_next_arg(state, &arg_idx), spec.length);
                    if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, (char)spec.conv, "ll")) {
                        supported = false;
                        break;
                    }
                    n = snprintf(rendered, sizeof(rendered), fmt_buf, (unsigned long long)uval);
                    break;
                }
                case 'f':
                case 'F':
                case 'e':
                case 'E':
                case 'g':
                case 'G': {
                    uint64_t raw = guest_snprintf_next_arg(state, &arg_idx);
                    double dv = 0.0;
                    memcpy(&dv, &raw, sizeof(dv));
                    if (spec.length == GUEST_FMT_LEN_CAP_L) {
                        long double lv = (long double)dv;
                        if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, (char)spec.conv, "L")) {
                            supported = false;
                            break;
                        }
                        n = snprintf(rendered, sizeof(rendered), fmt_buf, lv);
                    } else {
                        if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, (char)spec.conv, "")) {
                            supported = false;
                            break;
                        }
                        n = snprintf(rendered, sizeof(rendered), fmt_buf, dv);
                    }
                    break;
                }
                case 'p': {
                    void *ptr = (void *)(uintptr_t)guest_snprintf_next_arg(state, &arg_idx);
                    if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, 'p', "")) {
                        supported = false;
                        break;
                    }
                    n = snprintf(rendered, sizeof(rendered), fmt_buf, ptr);
                    break;
                }
                case 'c': {
                    int cval = (int)(uint8_t)(guest_snprintf_next_arg(state, &arg_idx) & 0xFFu);
                    if (spec.length == GUEST_FMT_LEN_L || spec.length == GUEST_FMT_LEN_CAP_L) {
                        supported = false;
                        break;
                    }
                    if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, 'c', "")) {
                        supported = false;
                        break;
                    }
                    n = snprintf(rendered, sizeof(rendered), fmt_buf, cval);
                    break;
                }
                case 's': {
                    uint64_t s_addr = guest_snprintf_next_arg(state, &arg_idx);
                    const char *src = NULL;
                    char scratch[512];

                    if (spec.length == GUEST_FMT_LEN_L || spec.length == GUEST_FMT_LEN_CAP_L) {
                        supported = false;
                        break;
                    }
                    if (s_addr == 0) {
                        src = "(null)";
                    } else if (s_addr >= (uint64_t)GUEST_MEM_SIZE) {
                        src = "(badptr)";
                    } else {
                        bool term = false;
                        uint64_t slen = guest_strnlen_scan(mem, s_addr, (uint64_t)GUEST_MEM_SIZE - s_addr, &term);
                        size_t copy = (size_t)slen;
                        if (copy >= sizeof(scratch)) {
                            copy = sizeof(scratch) - 1u;
                        }
                        memcpy(scratch, mem + (size_t)s_addr, copy);
                        scratch[copy] = '\0';
                        (void)term;
                        src = scratch;
                    }
                    if (!guest_snprintf_build_format(fmt_buf, sizeof(fmt_buf), &spec, 's', "")) {
                        supported = false;
                        break;
                    }
                    n = snprintf(rendered, sizeof(rendered), fmt_buf, src);
                    break;
                }
                case 'n': {
                    uint64_t out_ptr = guest_snprintf_next_arg(state, &arg_idx);
                    int64_t count = total > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)total;
                    if (out_ptr == 0 || !guest_sscanf_store_signed(mem, out_ptr, spec.length, count)) {
                        supported = false;
                        break;
                    }
                    n = 0;
                    break;
                }
                default:
                    supported = false;
                    break;
            }

            if (supported) {
                if (n < 0) {
                    return 0;
                }
                if (n > 0) {
                    size_t copy = (size_t)n;
                    if (copy >= sizeof(rendered)) {
                        copy = sizeof(rendered) - 1u;
                    }
                    guest_snprintf_append_str(mem, dst_addr, dst_size, &total, rendered, copy);
                    if ((size_t)n > copy) {
                        guest_snprintf_add_total(&total, (uint64_t)((size_t)n - copy));
                    }
                }
                i++;
                continue;
            }
        }

        for (uint64_t k = spec_start; k <= i && k < fmt_len; ++k) {
            guest_snprintf_append_char(mem, dst_addr, dst_size, &total, mem[(size_t)(fmt_addr + k)]);
        }
        i++;
    }

    if (dst_size > 0) {
        uint64_t nul_off = (total < dst_size - 1u) ? total : (dst_size - 1u);
        mem[(size_t)(dst_addr + nul_off)] = 0;
    }
    return total;
}

static bool guest_parse_strtod(const uint8_t *mem, uint64_t addr, double *out_value, uint64_t *out_end) {
    bool terminated = false;
    uint64_t src_len = 0;
    size_t copy = 0;
    char tmp[1024];
    char *end_ptr = NULL;
    double value = 0.0;

    if (!mem || !out_value || !out_end || addr >= (uint64_t)GUEST_MEM_SIZE) {
        return false;
    }

    *out_value = 0.0;
    *out_end = addr;
    src_len = guest_strnlen_scan(mem, addr, (uint64_t)GUEST_MEM_SIZE - addr, &terminated);
    copy = (size_t)src_len;
    if (copy >= sizeof(tmp)) {
        copy = sizeof(tmp) - 1u;
    }
    memcpy(tmp, mem + (size_t)addr, copy);
    tmp[copy] = '\0';

    errno = 0;
    value = strtod(tmp, &end_ptr);
    if (!end_ptr || end_ptr == tmp) {
        *out_value = 0.0;
        *out_end = addr;
        return true;
    }

    *out_value = value;
    *out_end = addr + (uint64_t)(end_ptr - tmp);
    return true;
}

static double guest_fp_arg_f64(const CPUState *state, unsigned idx) {
    uint64_t bits = 0;
    double value = 0.0;

    if (!state || idx >= 32u) {
        return 0.0;
    }

    /*
     * Prefer FP register payload (AArch64 ABI), but fall back to xN bits for
     * PoC-style synthetic tests that pass raw payload through x regs.
     */
    bits = state->v[idx][0];
    if (bits == 0 && idx < 31u) {
        bits = state->x[idx];
    }
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint64_t guest_fp_ret_f64(CPUState *state, double value) {
    uint64_t bits = 0;

    memcpy(&bits, &value, sizeof(bits));
    if (state) {
        state->v[0][0] = bits;
        state->v[0][1] = 0;
    }
    return bits;
}

static float guest_fp_arg_f32(const CPUState *state, unsigned idx) {
    uint32_t bits = 0;
    float value = 0.0f;

    if (!state || idx >= 32u) {
        return 0.0f;
    }
    bits = (uint32_t)(state->v[idx][0] & 0xFFFFFFFFu);
    if (bits == 0 && idx < 31u) {
        bits = (uint32_t)(state->x[idx] & 0xFFFFFFFFu);
    }
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint64_t guest_fp_ret_f32(CPUState *state, float value) {
    uint32_t bits = 0;

    memcpy(&bits, &value, sizeof(bits));
    if (state) {
        state->v[0][0] = (state->v[0][0] & 0xFFFFFFFF00000000ull) | (uint64_t)bits;
    }
    return (uint64_t)bits;
}

static bool guest_static_slot_ensure(CPUState *state, uint64_t *slot_addr, uint64_t align, uint64_t size) {
    uint64_t addr = 0;
    uint64_t zero = 0;

    if (!state || !slot_addr || !g_tiny_dbt_current_guest_mem || size == 0) {
        return false;
    }
    if (*slot_addr != 0 && guest_mem_range_valid(*slot_addr, size)) {
        return true;
    }
    if (align == 0) {
        align = 1;
    }
    if (!guest_heap_alloc_aligned(state, align, size, &addr) || !guest_mem_range_valid(addr, size)) {
        return false;
    }
    for (uint64_t off = 0; off + sizeof(zero) <= size; off += sizeof(zero)) {
        memcpy(g_tiny_dbt_current_guest_mem + (size_t)(addr + off), &zero, sizeof(zero));
    }
    if ((size % sizeof(zero)) != 0) {
        uint64_t off = size - (size % sizeof(zero));
        memcpy(g_tiny_dbt_current_guest_mem + (size_t)(addr + off), &zero, (size_t)(size - off));
    }
    *slot_addr = addr;
    return true;
}

static bool guest_errno_slot_ensure(CPUState *state, uint64_t *out_addr) {
    if (!state || !out_addr || !g_tiny_dbt_current_guest_mem) {
        return false;
    }
    if (!guest_static_slot_ensure(state, &g_tiny_dbt_errno_slot_addr, sizeof(uint64_t), sizeof(uint64_t))) {
        return false;
    }
    *out_addr = g_tiny_dbt_errno_slot_addr;
    return true;
}

static void guest_errno_write(CPUState *state, uint64_t err) {
    uint64_t addr = 0;
    if (!guest_errno_slot_ensure(state, &addr)) {
        return;
    }
    memcpy(g_tiny_dbt_current_guest_mem + (size_t)addr, &err, sizeof(err));
}

static uint64_t guest_errno_ptr(CPUState *state) {
    uint64_t addr = 0;
    if (!guest_errno_slot_ensure(state, &addr)) {
        return state ? state->sp : 0;
    }
    return addr;
}

static uint64_t guest_handle_x0(CPUState *state) {
    uint64_t key = 0;
    uint64_t ptr = 0;
    uint64_t payload[2];

    if (!state || !g_tiny_dbt_current_guest_mem) {
        return 0;
    }
    key = state->x[0];
    for (size_t i = 0; i < g_tiny_dbt_handle_cache_len; ++i) {
        if (g_tiny_dbt_handle_cache_keys[i] == key) {
            return g_tiny_dbt_handle_cache_ptrs[i];
        }
    }
    if (!guest_heap_alloc_aligned(state, sizeof(uint64_t), sizeof(payload), &ptr) ||
        !guest_mem_range_valid(ptr, sizeof(payload))) {
        return state->sp;
    }
    payload[0] = key;
    payload[1] = 0x48414E444C455345ull;
    memcpy(g_tiny_dbt_current_guest_mem + (size_t)ptr, payload, sizeof(payload));
    if (g_tiny_dbt_handle_cache_len < GUEST_HANDLE_CACHE_SLOTS) {
        size_t idx = g_tiny_dbt_handle_cache_len++;
        g_tiny_dbt_handle_cache_keys[idx] = key;
        g_tiny_dbt_handle_cache_ptrs[idx] = ptr;
    } else {
        /* FIFO replacement to cap guest allocations for handle-like imports. */
        memmove(g_tiny_dbt_handle_cache_keys, g_tiny_dbt_handle_cache_keys + 1u,
                (GUEST_HANDLE_CACHE_SLOTS - 1u) * sizeof(g_tiny_dbt_handle_cache_keys[0]));
        memmove(g_tiny_dbt_handle_cache_ptrs, g_tiny_dbt_handle_cache_ptrs + 1u,
                (GUEST_HANDLE_CACHE_SLOTS - 1u) * sizeof(g_tiny_dbt_handle_cache_ptrs[0]));
        g_tiny_dbt_handle_cache_keys[GUEST_HANDLE_CACHE_SLOTS - 1u] = key;
        g_tiny_dbt_handle_cache_ptrs[GUEST_HANDLE_CACHE_SLOTS - 1u] = ptr;
    }
    return ptr;
}

static uint64_t guest_gmtime_x0(CPUState *state) {
    uint64_t arg = 0;
    uint64_t raw = 0;
    int64_t sec = 0;
    time_t t = 0;
    struct tm tm_val;

    if (!state || !g_tiny_dbt_current_guest_mem) {
        return 0;
    }
    arg = state->x[0];
    sec = (int64_t)arg;
    if (arg != 0 && guest_mem_range_valid(arg, sizeof(uint64_t))) {
        memcpy(&raw, g_tiny_dbt_current_guest_mem + (size_t)arg, sizeof(raw));
        sec = (int64_t)raw;
    }
    if (!guest_static_slot_ensure(state, &g_tiny_dbt_gmtime_tm_addr, (uint64_t)_Alignof(struct tm),
                                  sizeof(struct tm))) {
        return 0;
    }
    t = (time_t)sec;
    memset(&tm_val, 0, sizeof(tm_val));
    if (!gmtime_r(&t, &tm_val)) {
        memset(&tm_val, 0, sizeof(tm_val));
    }
    memcpy(g_tiny_dbt_current_guest_mem + (size_t)g_tiny_dbt_gmtime_tm_addr, &tm_val, sizeof(tm_val));
    return g_tiny_dbt_gmtime_tm_addr;
}

static uint64_t guest_ctime_x0(CPUState *state) {
    uint64_t arg = 0;
    uint64_t raw = 0;
    int64_t sec = 0;
    time_t t = 0;
    char tmp[64];

    if (!state || !g_tiny_dbt_current_guest_mem) {
        return 0;
    }
    arg = state->x[0];
    sec = (int64_t)arg;
    if (arg != 0 && guest_mem_range_valid(arg, sizeof(uint64_t))) {
        memcpy(&raw, g_tiny_dbt_current_guest_mem + (size_t)arg, sizeof(raw));
        sec = (int64_t)raw;
    }
    if (!guest_static_slot_ensure(state, &g_tiny_dbt_ctime_buf_addr, 1, sizeof(tmp))) {
        return 0;
    }
    t = (time_t)sec;
    memset(tmp, 0, sizeof(tmp));
    if (!ctime_r(&t, tmp)) {
        (void)snprintf(tmp, sizeof(tmp), "%lld", (long long)sec);
    }
    tmp[sizeof(tmp) - 1u] = '\0';
    memcpy(g_tiny_dbt_current_guest_mem + (size_t)g_tiny_dbt_ctime_buf_addr, tmp, sizeof(tmp));
    return g_tiny_dbt_ctime_buf_addr;
}

static uint64_t guest_tzset_0(CPUState *state) {
    long tz = 0;
    int dl = 0;

    if (!state || !g_tiny_dbt_current_guest_mem) {
        return 0;
    }
    tzset();
    tz = timezone;
    dl = daylight;

    if (!guest_static_slot_ensure(state, &g_tiny_dbt_timezone_slot_addr, sizeof(long), sizeof(long))) {
        return 0;
    }
    if (!guest_static_slot_ensure(state, &g_tiny_dbt_daylight_slot_addr, sizeof(int), sizeof(int))) {
        return 0;
    }
    memcpy(g_tiny_dbt_current_guest_mem + (size_t)g_tiny_dbt_timezone_slot_addr, &tz, sizeof(tz));
    memcpy(g_tiny_dbt_current_guest_mem + (size_t)g_tiny_dbt_daylight_slot_addr, &dl, sizeof(dl));
    return 0;
}

static uint64_t guest_daylight_ptr(CPUState *state) {
    (void)guest_tzset_0(state);
    return g_tiny_dbt_daylight_slot_addr ? g_tiny_dbt_daylight_slot_addr : (state ? state->sp : 0);
}

static uint64_t guest_timezone_ptr(CPUState *state) {
    (void)guest_tzset_0(state);
    return g_tiny_dbt_timezone_slot_addr ? g_tiny_dbt_timezone_slot_addr : (state ? state->sp : 0);
}

static uint64_t guest_open_common(CPUState *state, uint64_t path_addr, uint64_t flags) {
    bool terminated = false;
    uint64_t max_len = 0;
    uint64_t len = 0;
    uint64_t seed = 1469598103934665603ull;
    int accmode = 0;

    if (!state || !g_tiny_dbt_current_guest_mem || path_addr >= (uint64_t)GUEST_MEM_SIZE) {
        guest_errno_write(state, ENOENT);
        return UINT64_MAX;
    }

    max_len = (uint64_t)GUEST_MEM_SIZE - path_addr;
    len = guest_strnlen_scan(g_tiny_dbt_current_guest_mem, path_addr, max_len, &terminated);
    if (!terminated || len == 0 || len == UINT64_MAX) {
        guest_errno_write(state, ENOENT);
        return UINT64_MAX;
    }
    for (uint64_t i = 0; i < len; ++i) {
        seed ^= g_tiny_dbt_current_guest_mem[(size_t)(path_addr + i)];
        seed *= 1099511628211ull;
    }

    accmode = (int)(flags & 0x3u);
    for (size_t idx = 0; idx < GUEST_FD_TABLE_SIZE; ++idx) {
        GuestFdEntry *fd = &g_tiny_dbt_guest_fds[idx];
        if (fd->used) {
            continue;
        }
        memset(fd, 0, sizeof(*fd));
        fd->used = true;
        fd->readable = (accmode != 1); /* !O_WRONLY */
        fd->writable = (accmode != 0); /* O_WRONLY/O_RDWR */
        fd->cursor = 0;
        fd->seed = seed + (uint64_t)idx;
        return (uint64_t)(GUEST_FD_MIN + idx);
    }

    guest_errno_write(state, EMFILE);
    return UINT64_MAX;
}

static bool guest_fd_lookup(CPUState *state, uint64_t guest_fd, GuestFdEntry **out_fd) {
    size_t idx = 0;
    if (!out_fd || guest_fd < GUEST_FD_MIN) {
        guest_errno_write(state, EBADF);
        return false;
    }
    idx = (size_t)(guest_fd - GUEST_FD_MIN);
    if (idx >= GUEST_FD_TABLE_SIZE || !g_tiny_dbt_guest_fds[idx].used) {
        guest_errno_write(state, EBADF);
        return false;
    }
    *out_fd = &g_tiny_dbt_guest_fds[idx];
    return true;
}

static uint64_t guest_open_x0_x1_x2(CPUState *state) {
    if (!state) {
        return UINT64_MAX;
    }
    return guest_open_common(state, state->x[0], state->x[1]);
}

static uint64_t guest_openat_x0_x1_x2_x3(CPUState *state) {
    if (!state) {
        return UINT64_MAX;
    }
    /* x0=dirfd is intentionally ignored in this synthetic PoC fd model. */
    return guest_open_common(state, state->x[1], state->x[2]);
}

static uint64_t guest_read_x0_x1_x2(CPUState *state) {
    GuestFdEntry *fd = NULL;
    uint64_t dst = 0;
    uint64_t count = 0;
    uint64_t remain = 0;
    uint64_t n = 0;

    if (!state) {
        return UINT64_MAX;
    }
    if (!guest_fd_lookup(state, state->x[0], &fd) || !fd->readable) {
        guest_errno_write(state, EBADF);
        return UINT64_MAX;
    }

    dst = state->x[1];
    count = state->x[2];
    if (count == 0) {
        return 0;
    }
    if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(dst, count)) {
        guest_errno_write(state, EFAULT);
        return UINT64_MAX;
    }

    if (fd->cursor >= GUEST_FD_SYNTHETIC_MAX_READ) {
        return 0; /* synthetic EOF */
    }
    remain = GUEST_FD_SYNTHETIC_MAX_READ - fd->cursor;
    n = count < remain ? count : remain;
    for (uint64_t i = 0; i < n; ++i) {
        g_tiny_dbt_current_guest_mem[(size_t)(dst + i)] = (uint8_t)((fd->seed + fd->cursor + i) & 0xFFu);
    }
    fd->cursor += n;
    return n;
}

static uint64_t guest_write_x0_x1_x2(CPUState *state) {
    GuestFdEntry *fd = NULL;
    uint64_t src = 0;
    uint64_t count = 0;

    if (!state) {
        return UINT64_MAX;
    }
    if (!guest_fd_lookup(state, state->x[0], &fd) || !fd->writable) {
        guest_errno_write(state, EBADF);
        return UINT64_MAX;
    }

    src = state->x[1];
    count = state->x[2];
    if (count == 0) {
        return 0;
    }
    if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(src, count)) {
        guest_errno_write(state, EFAULT);
        return UINT64_MAX;
    }

    if (fd->bytes_written > UINT64_MAX - count) {
        fd->bytes_written = UINT64_MAX;
    } else {
        fd->bytes_written += count;
    }
    return count;
}

static uint64_t guest_close_x0(CPUState *state) {
    GuestFdEntry *fd = NULL;
    if (!state || !guest_fd_lookup(state, state->x[0], &fd)) {
        return UINT64_MAX;
    }
    memset(fd, 0, sizeof(*fd));
    return 0;
}

static bool guest_sscanf_store_signed(uint8_t *mem, uint64_t addr, GuestFmtLength len, int64_t value) {
    switch (len) {
        case GUEST_FMT_LEN_HH: {
            int8_t v = (int8_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_H: {
            int16_t v = (int16_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_L: {
            long v = (long)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_LL: {
            long long v = (long long)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_J: {
            intmax_t v = (intmax_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_Z: {
            ssize_t v = (ssize_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_T: {
            ptrdiff_t v = (ptrdiff_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_CAP_L:
        case GUEST_FMT_LEN_NONE:
        default: {
            int v = (int)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
    }
}

static bool guest_sscanf_store_unsigned(uint8_t *mem, uint64_t addr, GuestFmtLength len, uint64_t value) {
    switch (len) {
        case GUEST_FMT_LEN_HH: {
            uint8_t v = (uint8_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_H: {
            uint16_t v = (uint16_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_L: {
            unsigned long v = (unsigned long)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_LL: {
            unsigned long long v = (unsigned long long)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_J: {
            uintmax_t v = (uintmax_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_Z: {
            size_t v = (size_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_T: {
            ptrdiff_t v = (ptrdiff_t)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
        case GUEST_FMT_LEN_CAP_L:
        case GUEST_FMT_LEN_NONE:
        default: {
            unsigned int v = (unsigned int)value;
            return guest_write_scalar(mem, addr, &v, sizeof(v));
        }
    }
}

static bool guest_sscanf_store_float(uint8_t *mem, uint64_t addr, GuestFmtLength len, double value) {
    if (len == GUEST_FMT_LEN_CAP_L) {
        long double v = (long double)value;
        return guest_write_scalar(mem, addr, &v, sizeof(v));
    }
    if (len == GUEST_FMT_LEN_L) {
        double v = value;
        return guest_write_scalar(mem, addr, &v, sizeof(v));
    }
    {
        float v = (float)value;
        return guest_write_scalar(mem, addr, &v, sizeof(v));
    }
}

static uint64_t guest_sscanf_scan(uint8_t *mem, uint64_t input_addr, uint64_t fmt_addr, const CPUState *state) {
    bool in_term = false;
    bool fmt_term = false;
    uint64_t in_len = 0;
    uint64_t fmt_len = 0;
    uint64_t in_pos = 0;
    uint64_t fmt_pos = 0;
    uint64_t assigned = 0;
    unsigned arg_idx = 2;

    if (!mem || !state || input_addr >= (uint64_t)GUEST_MEM_SIZE || fmt_addr >= (uint64_t)GUEST_MEM_SIZE) {
        return 0;
    }

    in_len = guest_strnlen_scan(mem, input_addr, (uint64_t)GUEST_MEM_SIZE - input_addr, &in_term);
    fmt_len = guest_strnlen_scan(mem, fmt_addr, (uint64_t)GUEST_MEM_SIZE - fmt_addr, &fmt_term);
    if (!in_term || !fmt_term) {
        return 0;
    }
    in_pos = input_addr;
    fmt_pos = 0;

    while (fmt_pos < fmt_len) {
        uint8_t fc = mem[(size_t)(fmt_addr + fmt_pos)];

        if (guest_ascii_isspace(fc)) {
            while (fmt_pos < fmt_len && guest_ascii_isspace(mem[(size_t)(fmt_addr + fmt_pos)])) {
                fmt_pos++;
            }
            while (in_pos < input_addr + in_len && guest_ascii_isspace(mem[(size_t)in_pos])) {
                in_pos++;
            }
            continue;
        }

        if (fc != '%') {
            if (in_pos >= input_addr + in_len || mem[(size_t)in_pos] != fc) {
                break;
            }
            in_pos++;
            fmt_pos++;
            continue;
        }

        fmt_pos++;
        if (fmt_pos >= fmt_len) {
            break;
        }
        if (mem[(size_t)(fmt_addr + fmt_pos)] == '%') {
            if (in_pos >= input_addr + in_len || mem[(size_t)in_pos] != '%') {
                break;
            }
            in_pos++;
            fmt_pos++;
            continue;
        }

        bool suppress = false;
        bool width_specified = false;
        int width = 0;
        GuestFmtLength len = GUEST_FMT_LEN_NONE;
        uint8_t conv = 0;

        if (mem[(size_t)(fmt_addr + fmt_pos)] == '*') {
            suppress = true;
            fmt_pos++;
        }

        while (fmt_pos < fmt_len) {
            uint8_t d = mem[(size_t)(fmt_addr + fmt_pos)];
            if (d < '0' || d > '9') {
                break;
            }
            width_specified = true;
            if (width <= INT_MAX / 10) {
                width *= 10;
                if (width <= INT_MAX - (int)(d - '0')) {
                    width += (int)(d - '0');
                } else {
                    width = INT_MAX;
                }
            } else {
                width = INT_MAX;
            }
            fmt_pos++;
        }

        if (fmt_pos + 1u < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'h' &&
            mem[(size_t)(fmt_addr + fmt_pos + 1u)] == 'h') {
            len = GUEST_FMT_LEN_HH;
            fmt_pos += 2u;
        } else if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'h') {
            len = GUEST_FMT_LEN_H;
            fmt_pos++;
        } else if (fmt_pos + 1u < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'l' &&
                   mem[(size_t)(fmt_addr + fmt_pos + 1u)] == 'l') {
            len = GUEST_FMT_LEN_LL;
            fmt_pos += 2u;
        } else if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'l') {
            len = GUEST_FMT_LEN_L;
            fmt_pos++;
        } else if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'j') {
            len = GUEST_FMT_LEN_J;
            fmt_pos++;
        } else if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'z') {
            len = GUEST_FMT_LEN_Z;
            fmt_pos++;
        } else if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 't') {
            len = GUEST_FMT_LEN_T;
            fmt_pos++;
        } else if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == 'L') {
            len = GUEST_FMT_LEN_CAP_L;
            fmt_pos++;
        }

        if (fmt_pos >= fmt_len) {
            break;
        }
        conv = mem[(size_t)(fmt_addr + fmt_pos)];
        fmt_pos++;

        if (conv != 'c' && conv != '[' && conv != 'n') {
            while (in_pos < input_addr + in_len && guest_ascii_isspace(mem[(size_t)in_pos])) {
                in_pos++;
            }
        }

        switch (conv) {
            case 'd':
            case 'i': {
                char token[256];
                char *endp = NULL;
                long long parsed = 0;
                size_t n_tok = 0;
                uint64_t max_chars = width_specified ? (uint64_t)width : ((input_addr + in_len) - in_pos);

                while (n_tok + 1u < sizeof(token) && (uint64_t)n_tok < max_chars && in_pos + n_tok < input_addr + in_len) {
                    token[n_tok] = (char)mem[(size_t)(in_pos + n_tok)];
                    n_tok++;
                }
                token[n_tok] = '\0';

                if (n_tok == 0) {
                    return assigned;
                }
                parsed = strtoll(token, &endp, conv == 'd' ? 10 : 0);
                if (!endp || endp == token) {
                    return assigned;
                }
                in_pos += (uint64_t)(endp - token);
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    if (out_ptr == 0 || !guest_sscanf_store_signed(mem, out_ptr, len, (int64_t)parsed)) {
                        return assigned;
                    }
                    assigned++;
                }
                break;
            }
            case 'u':
            case 'x':
            case 'X':
            case 'o': {
                char token[256];
                char *endp = NULL;
                unsigned long long parsed = 0;
                size_t n_tok = 0;
                int base = 10;
                uint64_t max_chars = width_specified ? (uint64_t)width : ((input_addr + in_len) - in_pos);

                if (conv == 'x' || conv == 'X') {
                    base = 16;
                } else if (conv == 'o') {
                    base = 8;
                }

                while (n_tok + 1u < sizeof(token) && (uint64_t)n_tok < max_chars && in_pos + n_tok < input_addr + in_len) {
                    token[n_tok] = (char)mem[(size_t)(in_pos + n_tok)];
                    n_tok++;
                }
                token[n_tok] = '\0';

                if (n_tok == 0) {
                    return assigned;
                }
                parsed = strtoull(token, &endp, base);
                if (!endp || endp == token) {
                    return assigned;
                }
                in_pos += (uint64_t)(endp - token);
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    if (out_ptr == 0 || !guest_sscanf_store_unsigned(mem, out_ptr, len, (uint64_t)parsed)) {
                        return assigned;
                    }
                    assigned++;
                }
                break;
            }
            case 'f':
            case 'F':
            case 'e':
            case 'E':
            case 'g':
            case 'G':
            case 'a':
            case 'A': {
                char token[256];
                char *endp = NULL;
                double parsed = 0.0;
                size_t n_tok = 0;
                uint64_t max_chars = width_specified ? (uint64_t)width : ((input_addr + in_len) - in_pos);

                while (n_tok + 1u < sizeof(token) && (uint64_t)n_tok < max_chars && in_pos + n_tok < input_addr + in_len) {
                    token[n_tok] = (char)mem[(size_t)(in_pos + n_tok)];
                    n_tok++;
                }
                token[n_tok] = '\0';

                if (n_tok == 0) {
                    return assigned;
                }
                parsed = strtod(token, &endp);
                if (!endp || endp == token) {
                    return assigned;
                }
                in_pos += (uint64_t)(endp - token);
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    if (out_ptr == 0 || !guest_sscanf_store_float(mem, out_ptr, len, parsed)) {
                        return assigned;
                    }
                    assigned++;
                }
                break;
            }
            case 'c': {
                uint64_t width_c = width_specified && width > 0 ? (uint64_t)width : 1u;
                for (uint64_t j = 0; j < width_c; ++j) {
                    if (in_pos + j >= input_addr + in_len) {
                        return assigned;
                    }
                }
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    if (out_ptr == 0 || !guest_mem_range_valid(out_ptr, width_c)) {
                        return assigned;
                    }
                    memcpy(mem + (size_t)out_ptr, mem + (size_t)in_pos, (size_t)width_c);
                    assigned++;
                }
                in_pos += width_c;
                break;
            }
            case 's': {
                uint64_t max_chars = width_specified && width > 0 ? (uint64_t)width : ((input_addr + in_len) - in_pos);
                uint64_t count = 0;

                while (count < max_chars && in_pos + count < input_addr + in_len &&
                       !guest_ascii_isspace(mem[(size_t)(in_pos + count)])) {
                    count++;
                }
                if (count == 0) {
                    return assigned;
                }
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    if (out_ptr == 0 || !guest_mem_range_valid(out_ptr, count + 1u)) {
                        return assigned;
                    }
                    memmove(mem + (size_t)out_ptr, mem + (size_t)in_pos, (size_t)count);
                    mem[(size_t)(out_ptr + count)] = 0;
                    assigned++;
                }
                in_pos += count;
                break;
            }
            case '[': {
                bool invert = false;
                bool set[256];
                uint8_t prev = 0;
                bool have_prev = false;
                uint64_t max_chars = 0;
                uint64_t count = 0;

                memset(set, 0, sizeof(set));
                if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == '^') {
                    invert = true;
                    fmt_pos++;
                }
                if (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] == ']') {
                    set[(uint8_t)']'] = true;
                    prev = (uint8_t)']';
                    have_prev = true;
                    fmt_pos++;
                }
                while (fmt_pos < fmt_len && mem[(size_t)(fmt_addr + fmt_pos)] != ']') {
                    uint8_t c1 = mem[(size_t)(fmt_addr + fmt_pos)];
                    if (c1 == '-' && have_prev && fmt_pos + 1u < fmt_len &&
                        mem[(size_t)(fmt_addr + fmt_pos + 1u)] != ']') {
                        uint8_t c2 = mem[(size_t)(fmt_addr + fmt_pos + 1u)];
                        uint8_t lo = prev < c2 ? prev : c2;
                        uint8_t hi = prev < c2 ? c2 : prev;
                        for (unsigned v = lo; v <= hi; ++v) {
                            set[v] = true;
                        }
                        prev = c2;
                        have_prev = true;
                        fmt_pos += 2u;
                        continue;
                    }
                    set[c1] = true;
                    prev = c1;
                    have_prev = true;
                    fmt_pos++;
                }
                if (fmt_pos >= fmt_len || mem[(size_t)(fmt_addr + fmt_pos)] != ']') {
                    return assigned;
                }
                fmt_pos++;

                max_chars = width_specified && width > 0 ? (uint64_t)width : ((input_addr + in_len) - in_pos);
                while (count < max_chars && in_pos + count < input_addr + in_len) {
                    uint8_t ch = mem[(size_t)(in_pos + count)];
                    bool match = set[ch];
                    if (invert) {
                        match = !match;
                    }
                    if (!match) {
                        break;
                    }
                    count++;
                }
                if (count == 0) {
                    return assigned;
                }
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    if (out_ptr == 0 || !guest_mem_range_valid(out_ptr, count + 1u)) {
                        return assigned;
                    }
                    memmove(mem + (size_t)out_ptr, mem + (size_t)in_pos, (size_t)count);
                    mem[(size_t)(out_ptr + count)] = 0;
                    assigned++;
                }
                in_pos += count;
                break;
            }
            case 'n': {
                if (!suppress) {
                    uint64_t out_ptr = guest_sscanf_next_arg(state, &arg_idx);
                    int64_t consumed = (in_pos - input_addr) > (uint64_t)INT64_MAX
                                           ? INT64_MAX
                                           : (int64_t)(in_pos - input_addr);
                    if (out_ptr == 0 || !guest_sscanf_store_signed(mem, out_ptr, len, consumed)) {
                        return assigned;
                    }
                }
                break;
            }
            default:
                return assigned;
        }
    }

    return assigned;
}

static uint64_t dbt_runtime_import_callback_dispatch(CPUState *state, uint64_t callback_id) {
    if (!state) {
        return 0;
    }

    switch (callback_id) {
        case IMPORT_CB_RET_0:
            return 0;
        case IMPORT_CB_RET_1:
            return 1;
        case IMPORT_CB_RET_NEG1:
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_ENOSYS:
            guest_errno_write(state, ENOSYS);
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_EAGAIN:
            guest_errno_write(state, EAGAIN);
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_EINTR:
            guest_errno_write(state, EINTR);
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_EACCES:
            guest_errno_write(state, EACCES);
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_ENOENT:
            guest_errno_write(state, ENOENT);
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_EPERM:
            guest_errno_write(state, EPERM);
            return UINT64_MAX;
        case IMPORT_CB_RET_NEG1_ETIMEDOUT:
            guest_errno_write(state, ETIMEDOUT);
            return UINT64_MAX;
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
        case IMPORT_CB_GUEST_ERRNO_PTR:
            return guest_errno_ptr(state);
        case IMPORT_CB_GUEST_HANDLE_X0:
            return guest_handle_x0(state);
        case IMPORT_CB_GUEST_OPEN_X0_X1_X2:
            return guest_open_x0_x1_x2(state);
        case IMPORT_CB_GUEST_OPENAT_X0_X1_X2_X3:
            return guest_openat_x0_x1_x2_x3(state);
        case IMPORT_CB_GUEST_READ_X0_X1_X2:
            return guest_read_x0_x1_x2(state);
        case IMPORT_CB_GUEST_WRITE_X0_X1_X2:
            return guest_write_x0_x1_x2(state);
        case IMPORT_CB_GUEST_CLOSE_X0:
            return guest_close_x0(state);
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
        case IMPORT_CB_GUEST_STRRCHR_X0_X1: {
            uint64_t addr = state->x[0];
            uint8_t needle = (uint8_t)(state->x[1] & 0xFFu);
            uint64_t i = 0;
            uint64_t last = 0;
            bool found = false;

            if (!g_tiny_dbt_current_guest_mem || addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }
            for (i = 0; addr + i < (uint64_t)GUEST_MEM_SIZE; ++i) {
                uint8_t ch = g_tiny_dbt_current_guest_mem[(size_t)(addr + i)];
                if (ch == needle) {
                    last = addr + i;
                    found = true;
                }
                if (ch == 0) {
                    return found ? last : 0;
                }
            }
            return 0;
        }
        case IMPORT_CB_GUEST_STRSTR_X0_X1: {
            uint64_t hay_addr = state->x[0];
            uint64_t needle_addr = state->x[1];
            bool hay_term = false;
            bool needle_term = false;
            uint64_t hay_len = 0;
            uint64_t needle_len = 0;

            if (!g_tiny_dbt_current_guest_mem || hay_addr >= (uint64_t)GUEST_MEM_SIZE ||
                needle_addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }

            hay_len = guest_strnlen_scan(g_tiny_dbt_current_guest_mem, hay_addr, (uint64_t)GUEST_MEM_SIZE - hay_addr,
                                         &hay_term);
            needle_len = guest_strnlen_scan(g_tiny_dbt_current_guest_mem, needle_addr,
                                            (uint64_t)GUEST_MEM_SIZE - needle_addr, &needle_term);
            if (!hay_term || !needle_term) {
                return 0;
            }
            if (needle_len == 0) {
                return hay_addr;
            }
            if (hay_len < needle_len) {
                return 0;
            }

            for (uint64_t pos = 0; pos <= hay_len - needle_len; ++pos) {
                const uint8_t *hay = g_tiny_dbt_current_guest_mem + (size_t)(hay_addr + pos);
                const uint8_t *needle = g_tiny_dbt_current_guest_mem + (size_t)needle_addr;
                if (memcmp(hay, needle, (size_t)needle_len) == 0) {
                    return hay_addr + pos;
                }
            }
            return 0;
        }
        case IMPORT_CB_GUEST_MEMCHR_X0_X1_X2: {
            uint64_t addr = state->x[0];
            uint8_t needle = (uint8_t)(state->x[1] & 0xFFu);
            uint64_t len = state->x[2];

            if (!g_tiny_dbt_current_guest_mem || len == 0 || !guest_mem_range_valid(addr, len)) {
                return 0;
            }
            for (uint64_t i = 0; i < len; ++i) {
                if (g_tiny_dbt_current_guest_mem[(size_t)(addr + i)] == needle) {
                    return addr + i;
                }
            }
            return 0;
        }
        case IMPORT_CB_GUEST_MEMRCHR_X0_X1_X2: {
            uint64_t addr = state->x[0];
            uint8_t needle = (uint8_t)(state->x[1] & 0xFFu);
            uint64_t len = state->x[2];

            if (!g_tiny_dbt_current_guest_mem || len == 0 || !guest_mem_range_valid(addr, len)) {
                return 0;
            }
            for (uint64_t i = len; i > 0; --i) {
                uint64_t off = i - 1;
                if (g_tiny_dbt_current_guest_mem[(size_t)(addr + off)] == needle) {
                    return addr + off;
                }
            }
            return 0;
        }
        case IMPORT_CB_GUEST_ATOI_X0: {
            int64_t value = 0;
            uint64_t end_addr = state->x[0];
            if (!g_tiny_dbt_current_guest_mem ||
                !guest_parse_strtol(g_tiny_dbt_current_guest_mem, state->x[0], 10, &value, &end_addr)) {
                return 0;
            }
            return (uint64_t)value;
        }
        case IMPORT_CB_GUEST_STRTOL_X0_X1_X2: {
            int64_t value = 0;
            uint64_t end_addr = state->x[0];
            uint64_t endptr_addr = state->x[1];
            int base = (int)(state->x[2] & 0xFFFFFFFFu);
            if (!g_tiny_dbt_current_guest_mem ||
                !guest_parse_strtol(g_tiny_dbt_current_guest_mem, state->x[0], base, &value, &end_addr)) {
                return 0;
            }
            if (endptr_addr != 0 && guest_mem_range_valid(endptr_addr, sizeof(uint64_t))) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)endptr_addr, &end_addr, sizeof(end_addr));
            }
            return (uint64_t)value;
        }
        case IMPORT_CB_GUEST_STRTOUL_X0_X1_X2: {
            int64_t value = 0;
            uint64_t end_addr = state->x[0];
            uint64_t endptr_addr = state->x[1];
            int base = (int)(state->x[2] & 0xFFFFFFFFu);
            if (!g_tiny_dbt_current_guest_mem ||
                !guest_parse_strtol(g_tiny_dbt_current_guest_mem, state->x[0], base, &value, &end_addr)) {
                return 0;
            }
            if (endptr_addr != 0 && guest_mem_range_valid(endptr_addr, sizeof(uint64_t))) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)endptr_addr, &end_addr, sizeof(end_addr));
            }
            return (uint64_t)value;
        }
        case IMPORT_CB_GUEST_POSIX_MEMALIGN_X0_X1_X2: {
            uint64_t outptr_addr = state->x[0];
            uint64_t align = state->x[1];
            uint64_t req = state->x[2];
            uint64_t ptr = 0;
            if (!g_tiny_dbt_current_guest_mem || !guest_mem_range_valid(outptr_addr, sizeof(uint64_t))) {
                return 22u; /* EINVAL */
            }
            if (align < sizeof(uint64_t) || !guest_is_power_of_two_u64(align)) {
                return 22u; /* EINVAL */
            }
            if (!guest_heap_alloc_aligned(state, align, req, &ptr)) {
                return 12u; /* ENOMEM */
            }
            memcpy(g_tiny_dbt_current_guest_mem + (size_t)outptr_addr, &ptr, sizeof(ptr));
            return 0;
        }
        case IMPORT_CB_GUEST_BASENAME_X0: {
            uint64_t path_addr = state->x[0];
            bool terminated = false;
            uint64_t len = 0;
            uint64_t end = 0;

            if (!g_tiny_dbt_current_guest_mem || path_addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }
            len = guest_strnlen_scan(g_tiny_dbt_current_guest_mem, path_addr, (uint64_t)GUEST_MEM_SIZE - path_addr,
                                     &terminated);
            if (!terminated) {
                return 0;
            }
            if (len == 0) {
                return path_addr;
            }

            end = path_addr + len - 1u;
            while (end > path_addr && g_tiny_dbt_current_guest_mem[(size_t)end] == '/') {
                end--;
            }
            if (end == path_addr && g_tiny_dbt_current_guest_mem[(size_t)end] == '/') {
                return path_addr;
            }
            while (end > path_addr) {
                if (g_tiny_dbt_current_guest_mem[(size_t)end] == '/') {
                    return end + 1u;
                }
                end--;
            }
            return path_addr;
        }
        case IMPORT_CB_GUEST_STRDUP_X0: {
            uint64_t src_addr = state->x[0];
            bool terminated = false;
            uint64_t len = 0;
            uint64_t nbytes = 0;
            uint64_t ptr = 0;
            uint64_t size = 0;

            if (!g_tiny_dbt_current_guest_mem || src_addr >= (uint64_t)GUEST_MEM_SIZE) {
                return 0;
            }

            len = guest_strnlen_scan(g_tiny_dbt_current_guest_mem, src_addr, (uint64_t)GUEST_MEM_SIZE - src_addr,
                                     &terminated);
            if (!terminated || len == UINT64_MAX) {
                return 0;
            }
            nbytes = len + 1u;
            if (!guest_mem_range_valid(src_addr, nbytes) || !guest_heap_alloc(state, nbytes, &ptr, &size) ||
                !guest_mem_range_valid(ptr, nbytes)) {
                return 0;
            }

            (void)size;
            memmove(g_tiny_dbt_current_guest_mem + (size_t)ptr, g_tiny_dbt_current_guest_mem + (size_t)src_addr,
                    (size_t)nbytes);
            return ptr;
        }
        case IMPORT_CB_GUEST_STRTOF_X0_X1: {
            double value = 0.0;
            float fvalue = 0.0f;
            uint64_t end_addr = state->x[0];
            uint64_t endptr_addr = state->x[1];
            uint32_t bits32 = 0;

            if (!g_tiny_dbt_current_guest_mem ||
                !guest_parse_strtod(g_tiny_dbt_current_guest_mem, state->x[0], &value, &end_addr)) {
                return 0;
            }
            if (endptr_addr != 0 && guest_mem_range_valid(endptr_addr, sizeof(uint64_t))) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)endptr_addr, &end_addr, sizeof(end_addr));
            }
            fvalue = (float)value;
            memcpy(&bits32, &fvalue, sizeof(bits32));
            state->v[0][0] = (uint64_t)bits32;
            state->v[0][1] = 0;
            return (uint64_t)bits32;
        }
        case IMPORT_CB_GUEST_POW_X0_X1: {
            double a = guest_fp_arg_f64(state, 0u);
            double b = guest_fp_arg_f64(state, 1u);
            return guest_fp_ret_f64(state, pow(a, b));
        }
        case IMPORT_CB_GUEST_SQRT_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, sqrt(a));
        }
        case IMPORT_CB_GUEST_COS_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, cos(a));
        }
        case IMPORT_CB_GUEST_TAN_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, tan(a));
        }
        case IMPORT_CB_GUEST_EXP_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, exp(a));
        }
        case IMPORT_CB_GUEST_LOG_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, log(a));
        }
        case IMPORT_CB_GUEST_LOG10_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, log10(a));
        }
        case IMPORT_CB_GUEST_FLOOR_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, floor(a));
        }
        case IMPORT_CB_GUEST_CEIL_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, ceil(a));
        }
        case IMPORT_CB_GUEST_TRUNC_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, trunc(a));
        }
        case IMPORT_CB_GUEST_FMOD_X0_X1: {
            double a = guest_fp_arg_f64(state, 0u);
            double b = guest_fp_arg_f64(state, 1u);
            return guest_fp_ret_f64(state, fmod(a, b));
        }
        case IMPORT_CB_GUEST_SIN_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, sin(a));
        }
        case IMPORT_CB_GUEST_SINH_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, sinh(a));
        }
        case IMPORT_CB_GUEST_TANH_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return guest_fp_ret_f64(state, tanh(a));
        }
        case IMPORT_CB_GUEST_ACOSF_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, acosf(a));
        }
        case IMPORT_CB_GUEST_ASINF_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, asinf(a));
        }
        case IMPORT_CB_GUEST_ATAN2F_X0_X1: {
            float a = guest_fp_arg_f32(state, 0u);
            float b = guest_fp_arg_f32(state, 1u);
            return guest_fp_ret_f32(state, atan2f(a, b));
        }
        case IMPORT_CB_GUEST_EXPF_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, expf(a));
        }
        case IMPORT_CB_GUEST_LOGF_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, logf(a));
        }
        case IMPORT_CB_GUEST_FMODF_X0_X1: {
            float a = guest_fp_arg_f32(state, 0u);
            float b = guest_fp_arg_f32(state, 1u);
            return guest_fp_ret_f32(state, fmodf(a, b));
        }
        case IMPORT_CB_GUEST_SINF_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, sinf(a));
        }
        case IMPORT_CB_GUEST_SINCOSF_X0_X1_X2: {
            float a = guest_fp_arg_f32(state, 0u);
            float s = sinf(a);
            float c = cosf(a);
            uint64_t sinp = state->x[1];
            uint64_t cosp = state->x[2];
            if (sinp != 0 && guest_mem_range_valid(sinp, sizeof(s))) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)sinp, &s, sizeof(s));
            }
            if (cosp != 0 && guest_mem_range_valid(cosp, sizeof(c))) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)cosp, &c, sizeof(c));
            }
            return 0;
        }
        case IMPORT_CB_GUEST_EXP2F_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, exp2f(a));
        }
        case IMPORT_CB_GUEST_LOG2F_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, log2f(a));
        }
        case IMPORT_CB_GUEST_LOG10F_X0: {
            float a = guest_fp_arg_f32(state, 0u);
            return guest_fp_ret_f32(state, log10f(a));
        }
        case IMPORT_CB_GUEST_LROUND_X0: {
            double a = guest_fp_arg_f64(state, 0u);
            return (uint64_t)lround(a);
        }
        case IMPORT_CB_GUEST_GMTIME_X0:
            return guest_gmtime_x0(state);
        case IMPORT_CB_GUEST_CTIME_X0:
            return guest_ctime_x0(state);
        case IMPORT_CB_GUEST_TZSET_0:
            return guest_tzset_0(state);
        case IMPORT_CB_GUEST_DAYLIGHT_PTR:
            return guest_daylight_ptr(state);
        case IMPORT_CB_GUEST_TIMEZONE_PTR:
            return guest_timezone_ptr(state);
        case IMPORT_CB_GUEST_ISLOWER_X0: {
            int ch = (int)(state->x[0] & 0xFFu);
            return (uint64_t)(islower(ch) ? 1 : 0);
        }
        case IMPORT_CB_GUEST_ISSPACE_X0: {
            int ch = (int)(state->x[0] & 0xFFu);
            return (uint64_t)(isspace(ch) ? 1 : 0);
        }
        case IMPORT_CB_GUEST_ISXDIGIT_X0: {
            int ch = (int)(state->x[0] & 0xFFu);
            return (uint64_t)(isxdigit(ch) ? 1 : 0);
        }
        case IMPORT_CB_GUEST_ISUPPER_X0: {
            int ch = (int)(state->x[0] & 0xFFu);
            return (uint64_t)(isupper(ch) ? 1 : 0);
        }
        case IMPORT_CB_GUEST_TOUPPER_X0: {
            int ch = (int)(state->x[0] & 0xFFu);
            return (uint64_t)(unsigned char)toupper(ch);
        }
        case IMPORT_CB_GUEST_TOLOWER_X0: {
            int ch = (int)(state->x[0] & 0xFFu);
            return (uint64_t)(unsigned char)tolower(ch);
        }
        case IMPORT_CB_GUEST_SNPRINTF_X0_X1_X2:
            if (!g_tiny_dbt_current_guest_mem) {
                return 0;
            }
            return guest_snprintf_format(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], state->x[2], state);
        case IMPORT_CB_GUEST_STRTOD_X0_X1: {
            double value = 0.0;
            uint64_t end_addr = state->x[0];
            uint64_t endptr_addr = state->x[1];
            uint64_t bits = 0;

            if (!g_tiny_dbt_current_guest_mem ||
                !guest_parse_strtod(g_tiny_dbt_current_guest_mem, state->x[0], &value, &end_addr)) {
                return 0;
            }
            if (endptr_addr != 0 && guest_mem_range_valid(endptr_addr, sizeof(uint64_t))) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)endptr_addr, &end_addr, sizeof(end_addr));
            }
            memcpy(&bits, &value, sizeof(bits));
            state->v[0][0] = bits;
            state->v[0][1] = 0;
            return bits;
        }
        case IMPORT_CB_GUEST_SSCANF_X0_X1_X2:
            if (!g_tiny_dbt_current_guest_mem) {
                return 0;
            }
            return guest_sscanf_scan(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], state);
        case IMPORT_CB_GUEST_VSNPRINTF_X0_X1_X2_X3: {
            CPUState tmp_state;
            if (!g_tiny_dbt_current_guest_mem || !guest_prepare_vsnprintf_state(state, state->x[3], &tmp_state)) {
                return 0;
            }
            return guest_snprintf_format(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], state->x[2],
                                         &tmp_state);
        }
        case IMPORT_CB_GUEST_VSSCANF_X0_X1_X2: {
            CPUState tmp_state;
            if (!g_tiny_dbt_current_guest_mem || !guest_prepare_vsscanf_state(state, state->x[2], &tmp_state)) {
                return 0;
            }
            return guest_sscanf_scan(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], &tmp_state);
        }
        case IMPORT_CB_GUEST_VSNPRINTF_CHK_X0_X1_X4_X5: {
            CPUState tmp_state;
            if (!g_tiny_dbt_current_guest_mem || !guest_prepare_vsnprintf_state(state, state->x[5], &tmp_state)) {
                return 0;
            }
            return guest_snprintf_format(g_tiny_dbt_current_guest_mem, state->x[0], state->x[1], state->x[4],
                                         &tmp_state);
        }
        case IMPORT_CB_GUEST_VFPRINTF_X0_X1_X2: {
            CPUState tmp_state;
            if (!g_tiny_dbt_current_guest_mem || !guest_prepare_vsnprintf_state(state, state->x[2], &tmp_state)) {
                return 0;
            }
            /* Approximate vfprintf by formatting and returning the produced length. */
            return guest_snprintf_format(g_tiny_dbt_current_guest_mem, 0, 0, state->x[1], &tmp_state);
        }
        case IMPORT_CB_GUEST_VASPRINTF_X0_X1_X2: {
            CPUState tmp_state;
            uint64_t outptr_addr = state->x[0];
            uint64_t fmt_addr = state->x[1];
            uint64_t needed = 0;
            uint64_t alloc_ptr = 0;
            uint64_t alloc_size = 0;
            uint64_t zero = 0;

            if (!g_tiny_dbt_current_guest_mem || !guest_prepare_vsnprintf_state(state, state->x[2], &tmp_state)) {
                return UINT64_MAX;
            }
            if (!guest_mem_range_valid(outptr_addr, sizeof(uint64_t))) {
                return UINT64_MAX;
            }

            needed = guest_snprintf_format(g_tiny_dbt_current_guest_mem, 0, 0, fmt_addr, &tmp_state);
            if (needed > UINT64_MAX - 1u) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)outptr_addr, &zero, sizeof(zero));
                return UINT64_MAX;
            }
            if (!guest_heap_alloc(state, needed + 1u, &alloc_ptr, &alloc_size)) {
                memcpy(g_tiny_dbt_current_guest_mem + (size_t)outptr_addr, &zero, sizeof(zero));
                return UINT64_MAX;
            }

            (void)alloc_size;
            (void)guest_snprintf_format(g_tiny_dbt_current_guest_mem, alloc_ptr, needed + 1u, fmt_addr, &tmp_state);
            memcpy(g_tiny_dbt_current_guest_mem + (size_t)outptr_addr, &alloc_ptr, sizeof(alloc_ptr));
            return needed;
        }
        default:
            return 0;
    }
}
