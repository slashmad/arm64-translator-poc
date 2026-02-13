static bool is_bcond_insn(uint32_t insn) {
    return (insn & 0xFF000010u) == 0x54000000u;
}

static bool is_b_insn(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x14000000u;
}

static bool is_bl_insn(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x94000000u;
}

static bool is_br_insn(uint32_t insn) {
    return (insn & 0xFFFFFC1Fu) == 0xD61F0000u;
}

static bool is_blr_insn(uint32_t insn) {
    return (insn & 0xFFFFFC1Fu) == 0xD63F0000u;
}

static bool is_cbz_cbnz_insn(uint32_t insn) {
    return (insn & 0x7E000000u) == 0x34000000u;
}

static bool is_tbz_tbnz_insn(uint32_t insn) {
    return (insn & 0x7E000000u) == 0x36000000u;
}

static bool is_ret_insn(uint32_t insn) {
    return (insn & 0xFFFFFC1Fu) == 0xD65F0000u;
}

static bool is_conditional_terminator(uint32_t insn) {
    return is_bcond_insn(insn) || is_cbz_cbnz_insn(insn) || is_tbz_tbnz_insn(insn);
}

static bool is_block_terminator(uint32_t insn) {
    return is_b_insn(insn) || is_bl_insn(insn) || is_br_insn(insn) || is_blr_insn(insn) ||
           is_conditional_terminator(insn) || is_ret_insn(insn);
}

static int branch_target_pc(uint32_t insn, size_t pc) {
    if (is_b_insn(insn)) {
        int32_t imm26 = sign_extend32(insn & 0x03FFFFFFu, 26);
        return (int)pc + imm26;
    }
    if (is_bcond_insn(insn)) {
        int32_t imm19 = sign_extend32((insn >> 5) & 0x7FFFFu, 19);
        return (int)pc + imm19;
    }
    if (is_cbz_cbnz_insn(insn)) {
        int32_t imm19 = sign_extend32((insn >> 5) & 0x7FFFFu, 19);
        return (int)pc + imm19;
    }
    if (is_tbz_tbnz_insn(insn)) {
        int32_t imm14 = sign_extend32((insn >> 5) & 0x3FFFu, 14);
        return (int)pc + imm14;
    }
    if (is_bl_insn(insn)) {
        int32_t imm26 = sign_extend32(insn & 0x03FFFFFFu, 26);
        return (int)pc + imm26;
    }
    return -1;
}

static void patch_rel32_at(uint8_t *out, size_t imm_off, size_t target_off) {
    int64_t disp = (int64_t)target_off - (int64_t)(imm_off + 4);
    if (disp < INT32_MIN || disp > INT32_MAX) {
        fprintf(stderr, "relative displacement too large\n");
        exit(1);
    }
    int32_t disp32 = (int32_t)disp;
    memcpy(out + imm_off, &disp32, sizeof(disp32));
}

static size_t collect_block_starts(const uint32_t *insns, size_t n_insn, bool *is_block_start, size_t *out_starts) {
    memset(is_block_start, 0, n_insn * sizeof(bool));
    if (n_insn == 0) {
        return 0;
    }
    is_block_start[0] = true;

    for (size_t pc = 0; pc < n_insn; ++pc) {
        uint32_t insn = insns[pc];
        int target = branch_target_pc(insn, pc);
        if (target >= 0) {
            if (target > (int)n_insn) {
                fprintf(stderr, "branch target out of range at pc=%zu\n", pc);
                exit(1);
            }
            if (target < (int)n_insn) {
                is_block_start[target] = true;
            }
        }
        if (is_block_terminator(insn) && pc + 1 < n_insn) {
            is_block_start[pc + 1] = true;
        }
    }

    size_t n_blocks = 0;
    for (size_t pc = 0; pc < n_insn; ++pc) {
        if (is_block_start[pc]) {
            out_starts[n_blocks++] = pc;
        }
    }
    return n_blocks;
}

static void emit_entry_dispatch(CodeBuf *cb, size_t n_insn, const uint64_t *entry_targets,
                                const uint64_t *entry_versions, OffPatchVec *exit_patches,
                                OffPatchVec *version_miss_patches) {
    /* r10 = state.pc >> 2 (instruction index) */
    x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, pc));
    x86_shift_imm(cb, 10, 1, 2);

    /* Out-of-range PC exits directly. */
    x86_cmp_imm32(cb, 10, (uint32_t)n_insn);
    offv_push(exit_patches, x86_ja_rel32(cb));

    /*
     * Direct-mapped entry cache: entry_targets[pc_index] = absolute translated
     * instruction address. Zero means no translated target -> fall back to exit.
     */
    x86_shift_imm(cb, 10, 0, 3); /* element index -> byte offset */
    x86_mov_rr(cb, 13, 10);      /* preserve entry byte offset */
    x86_mov_imm64(cb, 12, (uint64_t)(uintptr_t)entry_targets);
    x86_mov_r_from_mem_base_index_disp32(cb, 10, 12, 10, 0);
    x86_test_rr(cb, 10, 10);
    offv_push(exit_patches, x86_jz_rel32(cb));
    x86_mov_rr(cb, 12, 10); /* preserve target while validating dispatch version */
    x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)entry_versions);
    x86_mov_r_from_mem_base_index_disp32(cb, 10, 10, 13, 0);
    x86_mov_r_from_mem_base_disp32(cb, 13, 3, (int32_t)offsetof(CPUState, dispatch_version));
    x86_cmp_rr(cb, 10, 13);
    size_t to_version_miss = x86_jnz_rel32(cb);

    x86_mov_rr(cb, 13, 12); /* preserve target across emit_restore_rflags() */
    emit_restore_rflags(cb);
    x86_jmp_r(cb, 13);

    /* Version miss: capture current pc-index for targeted retagging in C runtime. */
    size_t version_miss_local_off = cb->len;
    patch_rel32_at(cb->data, to_version_miss, version_miss_local_off);
    x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, pc));
    x86_shift_imm(cb, 10, 1, 2);
    x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, version_miss_pc_index), 10);
    offv_push(version_miss_patches, x86_jmp_rel32(cb));
}

static void resolve_patches(const PatchVec *patches, const size_t *pc_to_off, size_t n_insn, uint8_t *out) {
    for (size_t i = 0; i < patches->len; ++i) {
        const Patch *p = &patches->items[i];
        if (p->target_pc < 0 || p->target_pc > (int)n_insn) {
            fprintf(stderr, "branch target out of range: pc=%d\n", p->target_pc);
            exit(1);
        }

        size_t target_off = pc_to_off[p->target_pc];
        if (target_off == SIZE_MAX) {
            fprintf(stderr, "untranslated branch target: pc=%d\n", p->target_pc);
            exit(1);
        }
        int64_t disp = (int64_t)target_off - (int64_t)(p->imm32_off + 4);
        if (disp < INT32_MIN || disp > INT32_MAX) {
            fprintf(stderr, "branch displacement too large\n");
            exit(1);
        }

        int32_t disp32 = (int32_t)disp;
        memcpy(out + p->imm32_off, &disp32, sizeof(disp32));
    }
}

static void resolve_offset_patches(const OffPatchVec *patches, size_t target_off, uint8_t *out) {
    for (size_t i = 0; i < patches->len; ++i) {
        patch_rel32_at(out, patches->items[i], target_off);
    }
}
