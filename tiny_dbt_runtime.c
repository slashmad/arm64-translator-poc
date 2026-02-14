#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
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
    IMPORT_CB_GUEST_STRCHR_X0_X1 = 0x5E,
    IMPORT_CB_GUEST_STRRCHR_X0_X1 = 0x5F,
    IMPORT_CB_GUEST_STRSTR_X0_X1 = 0x60,
    IMPORT_CB_GUEST_MEMCHR_X0_X1_X2 = 0x61,
    IMPORT_CB_GUEST_MEMRCHR_X0_X1_X2 = 0x62,
    IMPORT_CB_GUEST_ATOI_X0 = 0x63,
    IMPORT_CB_GUEST_STRTOL_X0_X1_X2 = 0x64,
    IMPORT_CB_GUEST_SNPRINTF_X0_X1_X2 = 0x65,
    IMPORT_CB_GUEST_STRTOD_X0_X1 = 0x66,
    IMPORT_CB_GUEST_SSCANF_X0_X1_X2 = 0x67
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
static bool guest_mem_range_valid(uint64_t addr, uint64_t len);
static int64_t guest_strcmp_impl(const uint8_t *mem, uint64_t a_addr, uint64_t b_addr, uint64_t limit, bool bounded);
static uint64_t guest_strnlen_scan(const uint8_t *mem, uint64_t addr, uint64_t max_len, bool *out_terminated);
static bool guest_parse_strtol(const uint8_t *mem, uint64_t addr, int base_arg, int64_t *out_value, uint64_t *out_end);
static bool guest_ascii_isspace(uint8_t ch);
static int guest_digit_value(uint8_t ch);
static bool guest_write_scalar(uint8_t *mem, uint64_t addr, const void *src, size_t len);
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
static uint64_t guest_sscanf_scan(uint8_t *mem, uint64_t input_addr, uint64_t fmt_addr, const CPUState *state);

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

static uint64_t guest_snprintf_next_arg(const CPUState *state, unsigned *arg_idx) {
    if (!state || !arg_idx) {
        return 0;
    }
    if (*arg_idx <= 7u) {
        uint64_t value = state->x[*arg_idx];
        (*arg_idx)++;
        return value;
    }
    return 0;
}

static uint64_t guest_sscanf_next_arg(const CPUState *state, unsigned *arg_idx) {
    if (!state || !arg_idx) {
        return 0;
    }
    if (*arg_idx <= 7u) {
        uint64_t value = state->x[*arg_idx];
        (*arg_idx)++;
        return value;
    }
    return 0;
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

        if (conv != 'c') {
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
        default:
            return 0;
    }
}
