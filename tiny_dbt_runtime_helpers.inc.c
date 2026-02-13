static void dbt_runtime_clear_ret_ic(CPUState *state) {
    if (!state) {
        return;
    }
    state->ret_ic_target = 0;
    state->ret_ic_version = 0;
}

static void dbt_runtime_bump_dispatch_version(CPUState *state) {
    state->dispatch_version++;
    dbt_runtime_clear_ret_ic(state);
}

static bool dbt_runtime_invalidate_slot(CPUState *state, uint64_t *entry_versions, const uint64_t *entry_targets,
                                        size_t n_insn, size_t pc_index, char *err, size_t err_cap) {
    if (pc_index > n_insn) {
        if (err && err_cap > 0) {
            snprintf(err, err_cap, "invalidate slot index out of range: %zu (max=%zu)", pc_index, n_insn);
        }
        return false;
    }
    if (entry_targets[pc_index] == 0) {
        if (err && err_cap > 0) {
            snprintf(err, err_cap, "cannot invalidate empty slot pc_index=%zu", pc_index);
        }
        return false;
    }
    entry_versions[pc_index] = 0;
    dbt_runtime_clear_ret_ic(state);
    return true;
}

static void dbt_runtime_invalidate_all_slots(CPUState *state, uint64_t *entry_versions, const uint64_t *entry_targets,
                                             size_t n_insn) {
    for (size_t pc = 0; pc <= n_insn; ++pc) {
        if (entry_targets[pc] != 0) {
            entry_versions[pc] = 0;
        }
    }
    dbt_runtime_clear_ret_ic(state);
}

static void dbt_runtime_retag_slot_or_all(CPUState *state, uint64_t *entry_versions, const uint64_t *entry_targets,
                                          size_t n_insn, uint64_t pc_index) {
    if (pc_index <= n_insn && entry_targets[pc_index] != 0) {
        entry_versions[pc_index] = state->dispatch_version;
        return;
    }
    for (size_t pc = 0; pc <= n_insn; ++pc) {
        if (entry_targets[pc] != 0) {
            entry_versions[pc] = state->dispatch_version;
        }
    }
}

static bool apply_pc_invalidation_spec(const char *spec, CPUState *state, uint64_t *entry_versions,
                                       const uint64_t *entry_targets, size_t n_insn, size_t *out_invalidated,
                                       char *err, size_t err_cap) {
    if (out_invalidated) {
        *out_invalidated = 0;
    }
    if (!spec || spec[0] == '\0') {
        return true;
    }

    size_t invalidated = 0;
    const char *p = spec;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        errno = 0;
        char *end = NULL;
        unsigned long long idx = strtoull(p, &end, 10);
        if (errno != 0 || end == p) {
            if (err && err_cap > 0) {
                snprintf(err, err_cap, "invalid TINY_DBT_INVALIDATE_PC_INDEXES near: %s", p);
            }
            return false;
        }
        while (*end == ' ' || *end == '\t') {
            end++;
        }
        if (*end != '\0' && *end != ',') {
            if (err && err_cap > 0) {
                snprintf(err, err_cap, "invalid separator in TINY_DBT_INVALIDATE_PC_INDEXES near: %s", end);
            }
            return false;
        }
        if (idx > n_insn) {
            if (err && err_cap > 0) {
                snprintf(err, err_cap, "TINY_DBT_INVALIDATE_PC_INDEXES index out of range: %llu (max=%zu)", idx,
                         n_insn);
            }
            return false;
        }

        if (!dbt_runtime_invalidate_slot(state, entry_versions, entry_targets, n_insn, (size_t)idx, err, err_cap)) {
            return false;
        }
        invalidated++;

        p = end;
    }

    if (out_invalidated) {
        *out_invalidated = invalidated;
    }
    return true;
}
