static char g_tiny_dbt_global_error[TINY_DBT_ERROR_CAP];

static void tiny_dbt_set_global_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_tiny_dbt_global_error, sizeof(g_tiny_dbt_global_error), fmt, ap);
    va_end(ap);
}

const char *tiny_dbt_last_error(const TinyDbt *dbt) {
    if (dbt && dbt->last_error[0] != '\0') {
        return dbt->last_error;
    }
    if (g_tiny_dbt_global_error[0] != '\0') {
        return g_tiny_dbt_global_error;
    }
    return "no error";
}

void tiny_dbt_destroy(TinyDbt *dbt) {
    if (!dbt) {
        return;
    }
    if (dbt->mem && dbt->cap > 0) {
        if (munmap(dbt->mem, dbt->cap) != 0) {
            perror("munmap");
        }
    }
    free(dbt->guest_mem);
    free(dbt->entry_targets);
    free(dbt->entry_versions);
    free(dbt);
}

TinyDbt *tiny_dbt_create_from_bytes(const uint8_t *code, size_t code_size) {
    g_tiny_dbt_global_error[0] = '\0';
    if (!code) {
        tiny_dbt_set_global_error("tiny_dbt_create_from_bytes: null code pointer");
        return NULL;
    }
    if (code_size == 0) {
        tiny_dbt_set_global_error("tiny_dbt_create_from_bytes: empty code buffer");
        return NULL;
    }
    if ((code_size & 0x3u) != 0) {
        tiny_dbt_set_global_error("tiny_dbt_create_from_bytes: code_size must be multiple of 4 (got %zu)", code_size);
        return NULL;
    }

    size_t n_insn = code_size / 4u;
    uint32_t *insns = calloc(n_insn, sizeof(*insns));
    if (!insns) {
        tiny_dbt_set_global_error("tiny_dbt_create_from_bytes: calloc failed");
        return NULL;
    }

    for (size_t i = 0; i < n_insn; ++i) {
        size_t off = i * 4u;
        /* AArch64 instructions are loaded as little-endian 32-bit words. */
        insns[i] = (uint32_t)code[off] | ((uint32_t)code[off + 1] << 8) | ((uint32_t)code[off + 2] << 16) |
                   ((uint32_t)code[off + 3] << 24);
    }

    TinyDbt *dbt = tiny_dbt_create(insns, n_insn);
    free(insns);
    return dbt;
}

size_t tiny_dbt_guest_mem_size(void) {
    return GUEST_MEM_SIZE;
}

bool tiny_dbt_guest_mem_read(TinyDbt *dbt, uint64_t addr, void *dst, size_t len) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_guest_mem_read: null runtime");
        return false;
    }
    dbt->last_error[0] = '\0';
    if (len == 0) {
        return true;
    }
    if (!dst) {
        tiny_dbt_set_error(dbt, "tiny_dbt_guest_mem_read: null destination");
        return false;
    }
    if (addr > (uint64_t)GUEST_MEM_SIZE || len > GUEST_MEM_SIZE || addr + (uint64_t)len > (uint64_t)GUEST_MEM_SIZE) {
        tiny_dbt_set_error(dbt, "tiny_dbt_guest_mem_read out of range: addr=%" PRIu64 " len=%zu (size=%d)", addr, len,
                           GUEST_MEM_SIZE);
        return false;
    }
    memcpy(dst, dbt->guest_mem + (size_t)addr, len);
    return true;
}

bool tiny_dbt_guest_mem_write(TinyDbt *dbt, uint64_t addr, const void *src, size_t len) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_guest_mem_write: null runtime");
        return false;
    }
    dbt->last_error[0] = '\0';
    if (len == 0) {
        return true;
    }
    if (!src) {
        tiny_dbt_set_error(dbt, "tiny_dbt_guest_mem_write: null source");
        return false;
    }
    if (addr > (uint64_t)GUEST_MEM_SIZE || len > GUEST_MEM_SIZE || addr + (uint64_t)len > (uint64_t)GUEST_MEM_SIZE) {
        tiny_dbt_set_error(dbt, "tiny_dbt_guest_mem_write out of range: addr=%" PRIu64 " len=%zu (size=%d)", addr, len,
                           GUEST_MEM_SIZE);
        return false;
    }
    memcpy(dbt->guest_mem + (size_t)addr, src, len);
    return true;
}

TinyDbt *tiny_dbt_create(const uint32_t *insns, size_t n_insn) {
    TinyDbt *dbt = calloc(1, sizeof(*dbt));
    bool *is_block_start = NULL;
    size_t *block_starts = NULL;
    size_t *pc_to_off = NULL;
    Patch *patch_store = NULL;
    OobPatch *oob_patch_store = NULL;
    UnsupportedPatch *unsupported_patch_store = NULL;
    size_t *exit_patch_store = NULL;
    size_t *version_miss_patch_store = NULL;
    size_t *dispatch_patch_store = NULL;
    long page_size = 0;
    size_t cap = 0;

    g_tiny_dbt_global_error[0] = '\0';
    if (!dbt) {
        tiny_dbt_set_global_error("calloc TinyDbt failed");
        return NULL;
    }
    dbt->last_error[0] = '\0';

    if (!insns || n_insn == 0) {
        tiny_dbt_set_error(dbt, "input opcode stream is empty");
        goto fail;
    }

    dbt->n_insn = n_insn;
    dbt->dispatch_version = DISPATCH_VERSION_INITIAL;

    is_block_start = calloc(n_insn, sizeof(*is_block_start));
    block_starts = calloc(n_insn, sizeof(*block_starts));
    pc_to_off = calloc(n_insn + 1, sizeof(*pc_to_off));
    dbt->entry_targets = calloc(n_insn + 1, sizeof(*dbt->entry_targets));
    dbt->entry_versions = calloc(n_insn + 1, sizeof(*dbt->entry_versions));
    patch_store = calloc(n_insn * 4 + 16, sizeof(*patch_store));
    oob_patch_store = calloc(n_insn * 8 + 8, sizeof(*oob_patch_store));
    unsupported_patch_store = calloc(n_insn * 8 + 8, sizeof(*unsupported_patch_store));
    exit_patch_store = calloc(n_insn * 8 + 16, sizeof(*exit_patch_store));
    version_miss_patch_store = calloc(n_insn * 8 + 16, sizeof(*version_miss_patch_store));
    dispatch_patch_store = calloc(n_insn * 8 + 16, sizeof(*dispatch_patch_store));
    dbt->guest_mem = calloc(GUEST_MEM_SIZE, 1);
    if (!is_block_start || !block_starts || !pc_to_off || !dbt->entry_targets || !dbt->entry_versions || !patch_store ||
        !oob_patch_store || !unsupported_patch_store || !exit_patch_store || !version_miss_patch_store ||
        !dispatch_patch_store || !dbt->guest_mem) {
        tiny_dbt_set_error(dbt, "calloc failed while creating runtime");
        goto fail;
    }

    for (size_t i = 0; i <= n_insn; ++i) {
        pc_to_off[i] = SIZE_MAX;
    }

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        tiny_dbt_set_error(dbt, "sysconf(_SC_PAGESIZE) failed");
        goto fail;
    }

    size_t estimated = n_insn * 320 + 1024;
    cap = (estimated + (size_t)page_size - 1) & ~((size_t)page_size - 1);
    dbt->mem = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dbt->mem == MAP_FAILED) {
        dbt->mem = NULL;
        tiny_dbt_set_error(dbt, "mmap failed: %s", strerror(errno));
        goto fail;
    }
    dbt->cap = cap;

    CodeBuf cb = {.data = dbt->mem, .len = 0, .cap = cap};
    PatchVec patches = {.items = patch_store, .len = 0, .cap = n_insn * 4 + 16};
    OobPatchVec oob_patches = {.items = oob_patch_store, .len = 0, .cap = n_insn * 8 + 8};
    UnsupportedPatchVec unsupported_patches = {
        .items = unsupported_patch_store, .len = 0, .cap = n_insn * 8 + 8};
    OffPatchVec exit_patches = {.items = exit_patch_store, .len = 0, .cap = n_insn * 8 + 16};
    OffPatchVec version_miss_patches = {.items = version_miss_patch_store, .len = 0, .cap = n_insn * 8 + 16};
    OffPatchVec dispatch_patches = {.items = dispatch_patch_store, .len = 0, .cap = n_insn * 8 + 16};

    size_t explicit_ret_count = 0;
    for (size_t pc = 0; pc < n_insn; ++pc) {
        if (is_ret_insn(insns[pc])) {
            explicit_ret_count++;
        }
    }

    size_t n_blocks = collect_block_starts(insns, n_insn, is_block_start, block_starts);

    emit_state_prologue(&cb);
    size_t dispatch_off = cb.len;
    emit_entry_dispatch(&cb, n_insn, dbt->entry_targets, dbt->entry_versions, &exit_patches, &version_miss_patches);

    for (size_t bi = 0; bi < n_blocks; ++bi) {
        size_t block_pc = block_starts[bi];

        bool emitted_terminator = false;
        for (size_t pc = block_pc; pc < n_insn; ++pc) {
            if (pc != block_pc && is_block_start[pc]) {
                pv_push(&patches, x86_jmp_rel32(&cb), (int)pc);
                emitted_terminator = true;
                break;
            }

            if (pc_to_off[pc] != SIZE_MAX) {
                tiny_dbt_set_error(dbt, "duplicate translation for pc=%zu", pc);
                goto fail;
            }
            pc_to_off[pc] = cb.len;
            translate_one(&cb, &patches, &oob_patches, &unsupported_patches, &dispatch_patches, insns[pc], pc,
                          dbt->guest_mem, n_insn, dbt->entry_targets, dbt->entry_versions);
            if (is_block_terminator(insns[pc])) {
                emitted_terminator = true;
                break;
            }
        }

        if (!emitted_terminator) {
            pv_push(&patches, x86_jmp_rel32(&cb), (int)n_insn);
        }
    }

    if (cb.len == 0 || explicit_ret_count == 0) {
        tiny_dbt_set_error(dbt, "translated stream must include RET");
        goto fail;
    }

    /* Out-of-bounds stubs set fault PC, force x0=-1, then branch to shared exit. */
    for (size_t i = 0; i < oob_patches.len; ++i) {
        size_t stub_off = cb.len;
        patch_rel32_at(cb.data, oob_patches.items[i].imm32_off, stub_off);

        emit_set_state_pc_bytes(&cb, oob_patches.items[i].fault_pc_bytes);
        emit_set_exit_reason(&cb, EXIT_REASON_OOB);
        x86_mov_imm64(&cb, 0, UINT64_MAX);
        offv_push(&exit_patches, x86_jmp_rel32(&cb));
    }

    /* Unsupported-opcode stubs are only hit when that path is executed. */
    for (size_t i = 0; i < unsupported_patches.len; ++i) {
        size_t stub_off = cb.len;
        patch_rel32_at(cb.data, unsupported_patches.items[i].imm32_off, stub_off);

        emit_set_state_pc_bytes(&cb, unsupported_patches.items[i].fault_pc_bytes);
        emit_set_exit_reason(&cb, EXIT_REASON_UNSUPPORTED);
        x86_mov_imm64(&cb, 10, unsupported_patches.items[i].fault_pc_bytes / 4u);
        x86_mov_mem_base_disp32_from_r(&cb, 3, (int32_t)offsetof(CPUState, unsupported_pc_index), 10);
        x86_mov_imm64(&cb, 10, unsupported_patches.items[i].insn);
        x86_mov_mem_base_disp32_from_r(&cb, 3, (int32_t)offsetof(CPUState, unsupported_insn), 10);
        x86_mov_imm64(&cb, 0, UINT64_MAX);
        offv_push(&exit_patches, x86_jmp_rel32(&cb));
    }

    /* Dispatch version mismatch exits so C runtime can retag and retry. */
    size_t version_miss_target_off = cb.len;
    emit_set_exit_reason(&cb, EXIT_REASON_VERSION_MISS);
    offv_push(&exit_patches, x86_jmp_rel32(&cb));

    /* Virtual end-of-stream target for branches that go to pc == n_insn. */
    size_t eos_target_off = cb.len;
    emit_set_state_pc_bytes(&cb, (uint64_t)(n_insn * 4u));
    offv_push(&exit_patches, x86_jmp_rel32(&cb));

    /* Shared function exit path: write tracked state back and return x0 in rax. */
    size_t exit_target_off = cb.len;
    emit_state_epilogue(&cb);

    pc_to_off[n_insn] = eos_target_off;
    resolve_patches(&patches, pc_to_off, n_insn, cb.data);
    resolve_offset_patches(&dispatch_patches, dispatch_off, cb.data);
    resolve_offset_patches(&version_miss_patches, version_miss_target_off, cb.data);
    resolve_offset_patches(&exit_patches, exit_target_off, cb.data);

    /* Populate direct-mapped entry cache with absolute translated instruction targets. */
    for (size_t pc = 0; pc < n_insn; ++pc) {
        if (pc_to_off[pc] != SIZE_MAX) {
            dbt->entry_targets[pc] = (uint64_t)(uintptr_t)(cb.data + pc_to_off[pc]);
            dbt->entry_versions[pc] = DISPATCH_VERSION_INITIAL;
        }
    }
    dbt->entry_targets[n_insn] = (uint64_t)(uintptr_t)(cb.data + eos_target_off);
    dbt->entry_versions[n_insn] = DISPATCH_VERSION_INITIAL;

    if (mprotect(dbt->mem, cap, PROT_READ | PROT_EXEC) != 0) {
        tiny_dbt_set_error(dbt, "mprotect failed: %s", strerror(errno));
        goto fail;
    }

    free(dispatch_patch_store);
    free(version_miss_patch_store);
    free(exit_patch_store);
    free(unsupported_patch_store);
    free(oob_patch_store);
    free(patch_store);
    free(pc_to_off);
    free(block_starts);
    free(is_block_start);
    return dbt;

fail:
    if (dbt->last_error[0] != '\0') {
        tiny_dbt_set_global_error("%s", dbt->last_error);
    }
    free(dispatch_patch_store);
    free(version_miss_patch_store);
    free(exit_patch_store);
    free(unsupported_patch_store);
    free(oob_patch_store);
    free(patch_store);
    free(pc_to_off);
    free(block_starts);
    free(is_block_start);
    tiny_dbt_destroy(dbt);
    return NULL;
}

bool tiny_dbt_invalidate_dispatch(TinyDbt *dbt) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_invalidate_dispatch: null runtime");
        return false;
    }
    dbt->dispatch_version++;
    dbt->last_error[0] = '\0';
    return true;
}

bool tiny_dbt_invalidate_all_slots(TinyDbt *dbt) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_invalidate_all_slots: null runtime");
        return false;
    }
    dbt_runtime_invalidate_all_slots(NULL, dbt->entry_versions, dbt->entry_targets, dbt->n_insn);
    dbt->last_error[0] = '\0';
    return true;
}

bool tiny_dbt_invalidate_pc_indexes(TinyDbt *dbt, const char *spec) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_invalidate_pc_indexes: null runtime");
        return false;
    }
    dbt->last_error[0] = '\0';
    return apply_pc_invalidation_spec(spec, NULL, dbt->entry_versions, dbt->entry_targets, dbt->n_insn, NULL,
                                      dbt->last_error, sizeof(dbt->last_error));
}

void tiny_dbt_state_init(TinyDbtCpuState *state) {
    if (!state) {
        return;
    }
    memset(state, 0, sizeof(*state));
    state->heap_base = 0x1000u;
    state->heap_brk = state->heap_base;
}

static bool tiny_dbt_run_internal(TinyDbt *dbt, CPUState *state, const TinyDbtRunOptions *opts, uint64_t *out_x0) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_run: null runtime");
        return false;
    }
    if (!state) {
        tiny_dbt_set_error(dbt, "tiny_dbt_run: null cpu state");
        return false;
    }
    dbt->last_error[0] = '\0';

    if (opts && opts->invalidate_all_slots) {
        dbt_runtime_invalidate_all_slots(state, dbt->entry_versions, dbt->entry_targets, dbt->n_insn);
    }
    if (opts && opts->invalidate_pc_indexes && opts->invalidate_pc_indexes[0] != '\0') {
        if (!apply_pc_invalidation_spec(opts->invalidate_pc_indexes, state, dbt->entry_versions, dbt->entry_targets,
                                        dbt->n_insn, NULL, dbt->last_error, sizeof(dbt->last_error))) {
            return false;
        }
    }
    if (opts && opts->invalidate_dispatch) {
        dbt_runtime_bump_dispatch_version(state);
    }
    dbt->dispatch_version = state->dispatch_version;

    bool debug_exit = opts && opts->debug_exit;

    size_t max_attempts = dbt->n_insn + 2;
    if (max_attempts < 3) {
        max_attempts = 3;
    }
    if (max_attempts > 4096) {
        max_attempts = 4096;
    }
    if (opts && opts->max_retries != 0) {
        if (opts->max_retries > 4096) {
            tiny_dbt_set_error(dbt, "--max-retries out of range (1..4096): %zu", opts->max_retries);
            return false;
        }
        max_attempts = opts->max_retries;
    }

    uint8_t *prev_guest_mem = g_tiny_dbt_current_guest_mem;
    g_tiny_dbt_current_guest_mem = dbt->guest_mem;

    typedef uint64_t (*JitFn)(CPUState *);
    JitFn fn = (JitFn)dbt->mem;
    uint64_t result = 0;
    for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
        state->exit_reason = EXIT_REASON_NONE;
        state->version_miss_pc_index = UINT64_MAX;
        state->unsupported_pc_index = UINT64_MAX;
        state->unsupported_insn = 0;
        result = fn(state);
        if (debug_exit) {
            fprintf(stderr,
                    "debug: attempt=%zu exit_reason=%" PRIu64 " pc_bytes=%" PRIu64
                    " dispatch_version=%" PRIu64 " miss_pc_index=%" PRIu64 "\n",
                    attempt + 1, state->exit_reason, state->pc, state->dispatch_version, state->version_miss_pc_index);
        }
        if (state->exit_reason != EXIT_REASON_VERSION_MISS) {
            break;
        }

        dbt_runtime_retag_slot_or_all(state, dbt->entry_versions, dbt->entry_targets, dbt->n_insn,
                                      state->version_miss_pc_index);
        dbt_runtime_clear_ret_ic(state);
    }
    if (state->exit_reason == EXIT_REASON_VERSION_MISS) {
        fprintf(stderr, "warning: dispatch version mismatch retry limit reached\n");
    }
    if (state->exit_reason == EXIT_REASON_UNSUPPORTED) {
        tiny_dbt_set_error(dbt, "unsupported opcode executed: pc=%" PRIu64 " insn=0x%08" PRIx32,
                           state->unsupported_pc_index, state->unsupported_insn);
        if (opts && opts->unsupported_log_path && opts->unsupported_log_path[0] != '\0') {
            FILE *f = fopen(opts->unsupported_log_path, "a");
            if (f) {
                fprintf(f, "pc=%" PRIu64 " insn=0x%08" PRIx32 "\n", state->unsupported_pc_index,
                        state->unsupported_insn);
                fclose(f);
            }
        }
        g_tiny_dbt_current_guest_mem = prev_guest_mem;
        return false;
    }
    state->nzcv = rflags_to_nzcv(state->rflags);

    if (result != state->x[0]) {
        fprintf(stderr, "warning: return value mismatch with state.x0\n");
    }
    dbt->dispatch_version = state->dispatch_version;
    if (out_x0) {
        *out_x0 = state->x[0];
    }
    g_tiny_dbt_current_guest_mem = prev_guest_mem;
    return true;
}

bool tiny_dbt_run_with_state(TinyDbt *dbt, TinyDbtCpuState *state, const TinyDbtRunOptions *opts, uint64_t *out_x0) {
    if (!dbt) {
        tiny_dbt_set_global_error("tiny_dbt_run_with_state: null runtime");
        return false;
    }
    if (!state) {
        tiny_dbt_set_error(dbt, "tiny_dbt_run_with_state: null cpu state");
        return false;
    }

    CPUState *cpu_state = (CPUState *)state;
    cpu_state->x[30] = dbt->n_insn * 4u; /* top-level RET exits through the end-of-stream target */
    if (cpu_state->heap_base == 0) {
        cpu_state->heap_base = 0x1000u;
    }
    if (cpu_state->heap_brk < cpu_state->heap_base) {
        cpu_state->heap_brk = cpu_state->heap_base;
    }
    if (cpu_state->heap_brk > (uint64_t)GUEST_MEM_SIZE) {
        cpu_state->heap_brk = (uint64_t)GUEST_MEM_SIZE;
    }
    if (cpu_state->dispatch_version == 0) {
        cpu_state->dispatch_version = dbt->dispatch_version;
    } else if (cpu_state->dispatch_version > dbt->dispatch_version) {
        dbt->dispatch_version = cpu_state->dispatch_version;
    }
    cpu_state->rflags = nzcv_to_rflags(cpu_state->nzcv);

    return tiny_dbt_run_internal(dbt, cpu_state, opts, out_x0);
}

bool tiny_dbt_run(TinyDbt *dbt, const TinyDbtRunOptions *opts, uint64_t *out_x0) {
    TinyDbtCpuState state;
    tiny_dbt_state_init(&state);
    return tiny_dbt_run_with_state(dbt, &state, opts, out_x0);
}
