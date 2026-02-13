#ifndef TINY_DBT_RUNTIME_H
#define TINY_DBT_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct TinyDbt TinyDbt;
enum {
    TINY_DBT_LR_STACK_DEPTH = 64
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
    uint64_t lr_stack[TINY_DBT_LR_STACK_DEPTH];
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
} TinyDbtCpuState;

typedef struct {
    bool invalidate_dispatch;
    bool invalidate_all_slots;
    const char *invalidate_pc_indexes;
    bool debug_exit;
    size_t max_retries; /* 0 => default policy */
    const char *unsupported_log_path;
} TinyDbtRunOptions;

TinyDbt *tiny_dbt_create(const uint32_t *insns, size_t n_insn);
TinyDbt *tiny_dbt_create_from_bytes(const uint8_t *code, size_t code_size);
void tiny_dbt_destroy(TinyDbt *dbt);

size_t tiny_dbt_guest_mem_size(void);
bool tiny_dbt_guest_mem_read(TinyDbt *dbt, uint64_t addr, void *dst, size_t len);
bool tiny_dbt_guest_mem_write(TinyDbt *dbt, uint64_t addr, const void *src, size_t len);

bool tiny_dbt_invalidate_dispatch(TinyDbt *dbt);
bool tiny_dbt_invalidate_all_slots(TinyDbt *dbt);
bool tiny_dbt_invalidate_pc_indexes(TinyDbt *dbt, const char *spec);

void tiny_dbt_state_init(TinyDbtCpuState *state);
bool tiny_dbt_run_with_state(TinyDbt *dbt, TinyDbtCpuState *state, const TinyDbtRunOptions *opts, uint64_t *out_x0);
bool tiny_dbt_run(TinyDbt *dbt, const TinyDbtRunOptions *opts, uint64_t *out_x0);
const char *tiny_dbt_last_error(const TinyDbt *dbt);

#endif
