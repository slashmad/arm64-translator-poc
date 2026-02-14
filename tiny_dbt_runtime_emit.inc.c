static void cb_need(CodeBuf *cb, size_t extra) {
    if (cb->len + extra <= cb->cap) {
        return;
    }
    fprintf(stderr, "code buffer overflow\n");
    exit(1);
}

static void emit1(CodeBuf *cb, uint8_t v) {
    cb_need(cb, 1);
    cb->data[cb->len++] = v;
}

static void emit4(CodeBuf *cb, uint32_t v) {
    cb_need(cb, 4);
    memcpy(cb->data + cb->len, &v, 4);
    cb->len += 4;
}

static void emit8(CodeBuf *cb, uint64_t v) {
    cb_need(cb, 8);
    memcpy(cb->data + cb->len, &v, 8);
    cb->len += 8;
}

static void pv_push(PatchVec *pv, size_t imm32_off, int target_pc) {
    if (pv->len >= pv->cap) {
        fprintf(stderr, "patch vector overflow\n");
        exit(1);
    }
    pv->items[pv->len].imm32_off = imm32_off;
    pv->items[pv->len].target_pc = target_pc;
    pv->len++;
}

static void oobv_push(OobPatchVec *ov, size_t imm32_off, uint64_t fault_pc_bytes) {
    if (ov->len >= ov->cap) {
        fprintf(stderr, "oob patch vector overflow\n");
        exit(1);
    }
    ov->items[ov->len].imm32_off = imm32_off;
    ov->items[ov->len].fault_pc_bytes = fault_pc_bytes;
    ov->len++;
}

static void unsupportedv_push(UnsupportedPatchVec *uv, size_t imm32_off, uint64_t fault_pc_bytes, uint32_t insn) {
    if (uv->len >= uv->cap) {
        fprintf(stderr, "unsupported patch vector overflow\n");
        exit(1);
    }
    uv->items[uv->len].imm32_off = imm32_off;
    uv->items[uv->len].fault_pc_bytes = fault_pc_bytes;
    uv->items[uv->len].insn = insn;
    uv->len++;
}

static void offv_push(OffPatchVec *ov, size_t imm32_off) {
    if (ov->len >= ov->cap) {
        fprintf(stderr, "offset patch vector overflow\n");
        exit(1);
    }
    ov->items[ov->len++] = imm32_off;
}

static int32_t sign_extend32(uint32_t value, unsigned bits) {
    uint32_t shift = 32u - bits;
    return (int32_t)(value << shift) >> shift;
}

static int highest_set_bit_u32(uint32_t value) {
    for (int bit = 31; bit >= 0; --bit) {
        if (value & (1u << bit)) {
            return bit;
        }
    }
    return -1;
}

static uint64_t ror_width_u64(uint64_t value, unsigned r, unsigned width) {
    uint64_t mask;
    unsigned rot;

    if (width == 0u || width > 64u) {
        fprintf(stderr, "invalid rotate width\n");
        exit(1);
    }

    mask = (width == 64u) ? UINT64_MAX : ((1ull << width) - 1ull);
    value &= mask;
    rot = r % width;
    if (rot == 0u) {
        return value;
    }
    return ((value >> rot) | (value << (width - rot))) & mask;
}

static uint64_t bitmask_width_u64(unsigned width) {
    if (width == 0u) {
        return 0u;
    }
    if (width >= 64u) {
        return UINT64_MAX;
    }
    return (1ull << width) - 1ull;
}

/*
 * Decode AArch64 logical-immediate bitmask.
 * Returns false for architecturally invalid encodings.
 */
static bool decode_logical_immediate_mask(unsigned sf, unsigned n, unsigned immr, unsigned imms, uint64_t *mask_out) {
    unsigned datasize = sf ? 64u : 32u;
    uint32_t combined = ((n & 1u) << 6) | ((~imms) & 0x3Fu);
    int len = highest_set_bit_u32(combined);
    uint32_t levels;
    unsigned s;
    unsigned r;
    unsigned esize;
    uint64_t welem;
    uint64_t pattern;
    uint64_t out = 0;
    unsigned pos;

    if (!mask_out) {
        return false;
    }
    if (!sf && n != 0u) {
        return false;
    }
    if (len < 1) {
        return false;
    }
    if ((unsigned)len > 6u) {
        return false;
    }
    levels = (1u << (unsigned)len) - 1u;
    if ((imms & levels) == levels) {
        return false;
    }

    s = imms & levels;
    r = immr & levels;
    esize = 1u << (unsigned)len;
    if (esize > datasize) {
        return false;
    }

    welem = (1ull << (s + 1u)) - 1ull;
    pattern = ror_width_u64(welem, r, esize);
    for (pos = 0; pos < datasize; pos += esize) {
        out |= pattern << pos;
    }
    if (datasize == 32u) {
        out &= 0xFFFFFFFFull;
    }
    *mask_out = out;
    return true;
}

static uint64_t nzcv_to_rflags(uint32_t nzcv) {
    uint64_t rflags = 0x2ull; /* bit 1 is fixed to 1 in x86 RFLAGS */
    if (nzcv & (1u << 31)) {
        rflags |= (1ull << 7); /* N -> SF */
    }
    if (nzcv & (1u << 30)) {
        rflags |= (1ull << 6); /* Z -> ZF */
    }
    if (nzcv & (1u << 29)) {
        rflags |= (1ull << 0); /* C -> CF */
    }
    if (nzcv & (1u << 28)) {
        rflags |= (1ull << 11); /* V -> OF */
    }
    return rflags;
}

static uint32_t rflags_to_nzcv(uint64_t rflags) {
    uint32_t nzcv = 0;
    if (rflags & (1ull << 7)) {
        nzcv |= (1u << 31); /* SF -> N */
    }
    if (rflags & (1ull << 6)) {
        nzcv |= (1u << 30); /* ZF -> Z */
    }
    if (rflags & (1ull << 0)) {
        nzcv |= (1u << 29); /* CF -> C */
    }
    if (rflags & (1ull << 11)) {
        nzcv |= (1u << 28); /* OF -> V */
    }
    return nzcv;
}

static void emit_rex_w(CodeBuf *cb, int reg_field, int rm_field) {
    /* 0100WRXB, we only use W/R/B here. */
    uint8_t rex = 0x48;
    rex |= (uint8_t)(((reg_field >> 3) & 1) << 2);
    rex |= (uint8_t)((rm_field >> 3) & 1);
    emit1(cb, rex);
}

static void emit_rex_32(CodeBuf *cb, int reg_field, int rm_field) {
    uint8_t rex = 0x40;
    rex |= (uint8_t)(((reg_field >> 3) & 1) << 2);
    rex |= (uint8_t)((rm_field >> 3) & 1);
    emit1(cb, rex);
}

static void emit_rex_w_sib(CodeBuf *cb, int reg_field, int index_field, int base_field) {
    uint8_t rex = 0x48;
    rex |= (uint8_t)(((reg_field >> 3) & 1) << 2);
    rex |= (uint8_t)(((index_field >> 3) & 1) << 1);
    rex |= (uint8_t)((base_field >> 3) & 1);
    emit1(cb, rex);
}

static void emit_rex_32_sib(CodeBuf *cb, int reg_field, int index_field, int base_field) {
    uint8_t rex = 0x40;
    rex |= (uint8_t)(((reg_field >> 3) & 1) << 2);
    rex |= (uint8_t)(((index_field >> 3) & 1) << 1);
    rex |= (uint8_t)((base_field >> 3) & 1);
    emit1(cb, rex);
}

/*
 * Minimal AArch64 -> x86_64 register map for this prototype.
 * Supports x0..x10 directly in host registers.
 */
static int map_reg(unsigned a64_reg) {
    switch (a64_reg) {
        case 0:
            return 0; /* rax */
        case 1:
            return 1; /* rcx */
        case 2:
            return 2; /* rdx */
        case 3:
            return 6; /* rsi */
        case 4:
            return 7; /* rdi */
        case 5:
            return 8; /* r8 */
        case 6:
            return 9; /* r9 */
        case 7:
            return 11; /* r11 */
        case 8:
            return 5; /* rbp */
        case 9:
            return 14; /* r14 */
        case 10:
            return 15; /* r15 */
        default:
            return -1;
    }
}

static void x86_mov_imm64(CodeBuf *cb, int reg, uint64_t imm) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, (uint8_t)(0xB8 + (reg & 7))); /* mov r64, imm64 */
    emit8(cb, imm);
}

static void x86_mov_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, src, dst);
    emit1(cb, 0x89); /* mov r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_mov_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, src, dst);
    emit1(cb, 0x89); /* mov r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_movsxd_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, dst, src);
    emit1(cb, 0x63); /* movsxd r64, r/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}

static void x86_push_r(CodeBuf *cb, int reg) {
    if (reg >= 8) {
        emit1(cb, 0x41);
    }
    emit1(cb, (uint8_t)(0x50 + (reg & 7)));
}

static void x86_pop_r(CodeBuf *cb, int reg) {
    if (reg >= 8) {
        emit1(cb, 0x41);
    }
    emit1(cb, (uint8_t)(0x58 + (reg & 7)));
}

static void x86_pushfq(CodeBuf *cb) {
    emit1(cb, 0x9C);
}

static void x86_popfq(CodeBuf *cb) {
    emit1(cb, 0x9D);
}

static void emit_capture_rflags_to_reg(CodeBuf *cb, int reg) {
    x86_pushfq(cb);
    x86_pop_r(cb, reg);
}

static void emit_load_rflags_from_reg(CodeBuf *cb, int reg) {
    x86_push_r(cb, reg);
    x86_popfq(cb);
}

static void x86_mov_r_from_mem_base_disp32(CodeBuf *cb, int dst, int base, int32_t disp) {
    if ((base & 7) == 4) {
        fprintf(stderr, "unsupported base register for mov load helper\n");
        exit(1);
    }
    emit_rex_w(cb, dst, base);
    emit1(cb, 0x8B); /* mov r64, r/m64 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | (base & 7))); /* mod=10 disp32 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_mem_base_disp32_from_r(CodeBuf *cb, int base, int32_t disp, int src) {
    if ((base & 7) == 4) {
        fprintf(stderr, "unsupported base register for mov store helper\n");
        exit(1);
    }
    emit_rex_w(cb, src, base);
    emit1(cb, 0x89); /* mov r/m64, r64 */
    emit1(cb, (uint8_t)(0x80 | ((src & 7) << 3) | (base & 7))); /* mod=10 disp32 */
    emit4(cb, (uint32_t)disp);
}

static void x86_add_imm32(CodeBuf *cb, int reg, uint32_t imm) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0x81); /* add r/m64, imm32 */
    emit1(cb, (uint8_t)(0xC0 | (reg & 7)));
    emit4(cb, imm);
}

static void x86_add_imm32_32(CodeBuf *cb, int reg, uint32_t imm) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0x81); /* add r/m32, imm32 */
    emit1(cb, (uint8_t)(0xC0 | (reg & 7)));
    emit4(cb, imm);
}

static void x86_sub_imm32(CodeBuf *cb, int reg, uint32_t imm) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0x81); /* sub r/m64, imm32 */
    emit1(cb, (uint8_t)(0xE8 | (reg & 7)));
    emit4(cb, imm);
}

static void x86_sub_imm32_32(CodeBuf *cb, int reg, uint32_t imm) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0x81); /* sub r/m32, imm32 */
    emit1(cb, (uint8_t)(0xE8 | (reg & 7)));
    emit4(cb, imm);
}

static void x86_cmp_imm32(CodeBuf *cb, int reg, uint32_t imm) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0x81); /* cmp r/m64, imm32 */
    emit1(cb, (uint8_t)(0xF8 | (reg & 7)));
    emit4(cb, imm);
}

static void x86_cmp_imm32_32(CodeBuf *cb, int reg, uint32_t imm) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0x81); /* cmp r/m32, imm32 */
    emit1(cb, (uint8_t)(0xF8 | (reg & 7)));
    emit4(cb, imm);
}

static void x86_add_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, src, dst);
    emit1(cb, 0x01); /* add r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_add_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, src, dst);
    emit1(cb, 0x01); /* add r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_sub_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, src, dst);
    emit1(cb, 0x29); /* sub r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_sub_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, src, dst);
    emit1(cb, 0x29); /* sub r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_cmp_rr(CodeBuf *cb, int lhs, int rhs) {
    emit_rex_w(cb, rhs, lhs);
    emit1(cb, 0x39); /* cmp r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((rhs & 7) << 3) | (lhs & 7)));
}

static void x86_cmp_rr32(CodeBuf *cb, int lhs, int rhs) {
    emit_rex_32(cb, rhs, lhs);
    emit1(cb, 0x39); /* cmp r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((rhs & 7) << 3) | (lhs & 7)));
}

static void x86_and_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, src, dst);
    emit1(cb, 0x21); /* and r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_and_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, src, dst);
    emit1(cb, 0x21); /* and r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_or_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, src, dst);
    emit1(cb, 0x09); /* or r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_or_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, src, dst);
    emit1(cb, 0x09); /* or r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_xor_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, src, dst);
    emit1(cb, 0x31); /* xor r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_xor_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, src, dst);
    emit1(cb, 0x31); /* xor r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void x86_imul_rr(CodeBuf *cb, int dst, int src) {
    emit_rex_w(cb, dst, src);
    emit1(cb, 0x0F);
    emit1(cb, 0xAF); /* imul r64, r/m64 */
    emit1(cb, (uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}

static void x86_imul_rr32(CodeBuf *cb, int dst, int src) {
    emit_rex_32(cb, dst, src);
    emit1(cb, 0x0F);
    emit1(cb, 0xAF); /* imul r32, r/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}

static void x86_not_r(CodeBuf *cb, int reg) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0xF7); /* not r/m64 */
    emit1(cb, (uint8_t)(0xD0 | (reg & 7))); /* /2 */
}

static void x86_not_r32(CodeBuf *cb, int reg) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0xF7); /* not r/m32 */
    emit1(cb, (uint8_t)(0xD0 | (reg & 7))); /* /2 */
}

static void emit_rex_simd_w(CodeBuf *cb, bool w, int reg_field, int rm_field) {
    uint8_t rex = 0x40;
    if (w) {
        rex |= 0x08;
    }
    rex |= (uint8_t)(((reg_field >> 3) & 1) << 2);
    rex |= (uint8_t)((rm_field >> 3) & 1);
    if (rex != 0x40) {
        emit1(cb, rex);
    }
}

static void emit_rex_simd(CodeBuf *cb, int reg_field, int rm_field) {
    emit_rex_simd_w(cb, false, reg_field, rm_field);
}

static void x86_sse_load_xmm_from_mem_base_disp32(CodeBuf *cb, uint8_t prefix, int dst_xmm, int base, int32_t disp) {
    if ((base & 7) == 4) {
        fprintf(stderr, "unsupported base register for SSE load helper\n");
        exit(1);
    }
    emit1(cb, prefix);
    emit_rex_simd(cb, dst_xmm, base);
    emit1(cb, 0x0F);
    emit1(cb, 0x10); /* movss/movsd xmm, m32/m64 */
    emit1(cb, (uint8_t)(0x80 | ((dst_xmm & 7) << 3) | (base & 7))); /* mod=10 disp32 */
    emit4(cb, (uint32_t)disp);
}

static void x86_sse_store_mem_base_disp32_from_xmm(CodeBuf *cb, uint8_t prefix, int base, int src_xmm, int32_t disp) {
    if ((base & 7) == 4) {
        fprintf(stderr, "unsupported base register for SSE store helper\n");
        exit(1);
    }
    emit1(cb, prefix);
    emit_rex_simd(cb, src_xmm, base);
    emit1(cb, 0x0F);
    emit1(cb, 0x11); /* movss/movsd m32/m64, xmm */
    emit1(cb, (uint8_t)(0x80 | ((src_xmm & 7) << 3) | (base & 7))); /* mod=10 disp32 */
    emit4(cb, (uint32_t)disp);
}

static void x86_sse_binop_rr(CodeBuf *cb, uint8_t prefix, uint8_t opcode, int dst_xmm, int src_xmm) {
    emit1(cb, prefix);
    emit_rex_simd(cb, dst_xmm, src_xmm);
    emit1(cb, 0x0F);
    emit1(cb, opcode); /* add/sub/mul scalar */
    emit1(cb, (uint8_t)(0xC0 | ((dst_xmm & 7) << 3) | (src_xmm & 7)));
}

static void x86_movss_xmm_from_mem_base_disp32(CodeBuf *cb, int dst_xmm, int base, int32_t disp) {
    x86_sse_load_xmm_from_mem_base_disp32(cb, 0xF3, dst_xmm, base, disp);
}

static void x86_movsd_xmm_from_mem_base_disp32(CodeBuf *cb, int dst_xmm, int base, int32_t disp) {
    x86_sse_load_xmm_from_mem_base_disp32(cb, 0xF2, dst_xmm, base, disp);
}

static void x86_movss_mem_base_disp32_from_xmm(CodeBuf *cb, int base, int src_xmm, int32_t disp) {
    x86_sse_store_mem_base_disp32_from_xmm(cb, 0xF3, base, src_xmm, disp);
}

static void x86_movsd_mem_base_disp32_from_xmm(CodeBuf *cb, int base, int src_xmm, int32_t disp) {
    x86_sse_store_mem_base_disp32_from_xmm(cb, 0xF2, base, src_xmm, disp);
}

static void x86_addss_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF3, 0x58, dst_xmm, src_xmm);
}

static void x86_addsd_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF2, 0x58, dst_xmm, src_xmm);
}

static void x86_subss_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF3, 0x5C, dst_xmm, src_xmm);
}

static void x86_subsd_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF2, 0x5C, dst_xmm, src_xmm);
}

static void x86_mulss_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF3, 0x59, dst_xmm, src_xmm);
}

static void x86_mulsd_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF2, 0x59, dst_xmm, src_xmm);
}

static void x86_divss_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF3, 0x5E, dst_xmm, src_xmm);
}

static void x86_divsd_rr(CodeBuf *cb, int dst_xmm, int src_xmm) {
    x86_sse_binop_rr(cb, 0xF2, 0x5E, dst_xmm, src_xmm);
}

static void x86_cvtsi2ss_xmm_from_r32(CodeBuf *cb, int dst_xmm, int src_reg) {
    emit1(cb, 0xF3);
    emit_rex_simd(cb, dst_xmm, src_reg);
    emit1(cb, 0x0F);
    emit1(cb, 0x2A); /* cvtsi2ss xmm, r/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_xmm & 7) << 3) | (src_reg & 7)));
}

static void x86_cvtsi2ss_xmm_from_r64(CodeBuf *cb, int dst_xmm, int src_reg) {
    emit1(cb, 0xF3);
    emit_rex_simd_w(cb, true, dst_xmm, src_reg);
    emit1(cb, 0x0F);
    emit1(cb, 0x2A); /* cvtsi2ss xmm, r/m64 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_xmm & 7) << 3) | (src_reg & 7)));
}

static void x86_cvtsi2sd_xmm_from_r32(CodeBuf *cb, int dst_xmm, int src_reg) {
    emit1(cb, 0xF2);
    emit_rex_simd(cb, dst_xmm, src_reg);
    emit1(cb, 0x0F);
    emit1(cb, 0x2A); /* cvtsi2sd xmm, r/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_xmm & 7) << 3) | (src_reg & 7)));
}

static void x86_cvtsi2sd_xmm_from_r64(CodeBuf *cb, int dst_xmm, int src_reg) {
    emit1(cb, 0xF2);
    emit_rex_simd_w(cb, true, dst_xmm, src_reg);
    emit1(cb, 0x0F);
    emit1(cb, 0x2A); /* cvtsi2sd xmm, r/m64 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_xmm & 7) << 3) | (src_reg & 7)));
}

static void x86_cvttss2si_r32_from_xmm(CodeBuf *cb, int dst_reg, int src_xmm) {
    emit1(cb, 0xF3);
    emit_rex_simd(cb, dst_reg, src_xmm);
    emit1(cb, 0x0F);
    emit1(cb, 0x2C); /* cvttss2si r32, xmm/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_reg & 7) << 3) | (src_xmm & 7)));
}

static void x86_cvttss2si_r64_from_xmm(CodeBuf *cb, int dst_reg, int src_xmm) {
    emit1(cb, 0xF3);
    emit_rex_simd_w(cb, true, dst_reg, src_xmm);
    emit1(cb, 0x0F);
    emit1(cb, 0x2C); /* cvttss2si r64, xmm/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_reg & 7) << 3) | (src_xmm & 7)));
}

static void x86_cvttsd2si_r32_from_xmm(CodeBuf *cb, int dst_reg, int src_xmm) {
    emit1(cb, 0xF2);
    emit_rex_simd(cb, dst_reg, src_xmm);
    emit1(cb, 0x0F);
    emit1(cb, 0x2C); /* cvttsd2si r32, xmm/m64 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_reg & 7) << 3) | (src_xmm & 7)));
}

static void x86_cvttsd2si_r64_from_xmm(CodeBuf *cb, int dst_reg, int src_xmm) {
    emit1(cb, 0xF2);
    emit_rex_simd_w(cb, true, dst_reg, src_xmm);
    emit1(cb, 0x0F);
    emit1(cb, 0x2C); /* cvttsd2si r64, xmm/m64 */
    emit1(cb, (uint8_t)(0xC0 | ((dst_reg & 7) << 3) | (src_xmm & 7)));
}

static void x86_ucomiss_rr(CodeBuf *cb, int lhs_xmm, int rhs_xmm) {
    emit1(cb, 0x0F);
    emit1(cb, 0x2E); /* ucomiss xmm, xmm/m32 */
    emit1(cb, (uint8_t)(0xC0 | ((lhs_xmm & 7) << 3) | (rhs_xmm & 7)));
}

static void x86_ucomisd_rr(CodeBuf *cb, int lhs_xmm, int rhs_xmm) {
    emit1(cb, 0x66);
    emit1(cb, 0x0F);
    emit1(cb, 0x2E); /* ucomisd xmm, xmm/m64 */
    emit1(cb, (uint8_t)(0xC0 | ((lhs_xmm & 7) << 3) | (rhs_xmm & 7)));
}

static void x86_mov_r_from_mem_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_w_sib(cb, dst, index, base);
    emit1(cb, 0x8B); /* mov r64, r/m64 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_mem_base_index_disp32_from_r(CodeBuf *cb, int base, int index, int src, int32_t disp) {
    emit_rex_w_sib(cb, src, index, base);
    emit1(cb, 0x89); /* mov r/m64, r64 */
    emit1(cb, (uint8_t)(0x80 | ((src & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_lea_r_from_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_w_sib(cb, dst, index, base);
    emit1(cb, 0x8D); /* lea r64, m */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_r32_from_mem_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_32_sib(cb, dst, index, base);
    emit1(cb, 0x8B); /* mov r32, r/m32 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_r32_from_mem_base_disp32(CodeBuf *cb, int dst, int base, int32_t disp) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_mov_r32_from_mem_base_index_disp32(cb, dst, base, 4, disp);
}

static void x86_mov_mem_base_index_disp32_from_r32(CodeBuf *cb, int base, int index, int src, int32_t disp) {
    emit_rex_32_sib(cb, src, index, base);
    emit1(cb, 0x89); /* mov r/m32, r32 */
    emit1(cb, (uint8_t)(0x80 | ((src & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_mem_base_disp32_from_r32(CodeBuf *cb, int base, int src, int32_t disp) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_mov_mem_base_index_disp32_from_r32(cb, base, 4, src, disp);
}

static void x86_movzx_r32_from_mem8_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_32_sib(cb, dst, index, base);
    emit1(cb, 0x0F);
    emit1(cb, 0xB6); /* movzx r32, r/m8 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_movzx_r32_from_mem8_base_disp32(CodeBuf *cb, int dst, int base, int32_t disp) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_movzx_r32_from_mem8_base_index_disp32(cb, dst, base, 4, disp);
}

static void x86_movzx_r32_from_mem16_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_32_sib(cb, dst, index, base);
    emit1(cb, 0x0F);
    emit1(cb, 0xB7); /* movzx r32, r/m16 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_movzx_r32_from_mem16_base_disp32(CodeBuf *cb, int dst, int base, int32_t disp) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_movzx_r32_from_mem16_base_index_disp32(cb, dst, base, 4, disp);
}

static void x86_movsx_r64_from_mem8_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_w_sib(cb, dst, index, base);
    emit1(cb, 0x0F);
    emit1(cb, 0xBE); /* movsx r64, r/m8 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_movsx_r64_from_mem16_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_w_sib(cb, dst, index, base);
    emit1(cb, 0x0F);
    emit1(cb, 0xBF); /* movsx r64, r/m16 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_mem8_base_index_disp32_from_r(CodeBuf *cb, int base, int index, int src, int32_t disp) {
    emit_rex_32_sib(cb, src, index, base);
    emit1(cb, 0x88); /* mov r/m8, r8 */
    emit1(cb, (uint8_t)(0x80 | ((src & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_mem8_base_disp32_from_r(CodeBuf *cb, int base, int src, int32_t disp) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_mov_mem8_base_index_disp32_from_r(cb, base, 4, src, disp);
}

static void x86_mov_mem16_base_index_disp32_from_r(CodeBuf *cb, int base, int index, int src, int32_t disp) {
    emit1(cb, 0x66); /* operand-size prefix -> 16-bit */
    emit_rex_32_sib(cb, src, index, base);
    emit1(cb, 0x89); /* mov r/m16, r16 */
    emit1(cb, (uint8_t)(0x80 | ((src & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_mov_mem16_base_disp32_from_r(CodeBuf *cb, int base, int src, int32_t disp) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_mov_mem16_base_index_disp32_from_r(cb, base, 4, src, disp);
}

static void x86_lock_cmpxchg_mem_base_index_disp32_from_r(CodeBuf *cb, int base, int index, int src, int32_t disp,
                                                           unsigned access_size) {
    emit1(cb, 0xF0); /* lock */
    switch (access_size) {
        case 1:
            emit_rex_32_sib(cb, src, index, base);
            emit1(cb, 0x0F);
            emit1(cb, 0xB0); /* cmpxchg r/m8, r8 */
            break;
        case 2:
            emit1(cb, 0x66); /* operand-size prefix -> 16-bit */
            emit_rex_32_sib(cb, src, index, base);
            emit1(cb, 0x0F);
            emit1(cb, 0xB1); /* cmpxchg r/m16, r16 */
            break;
        case 4:
            emit_rex_32_sib(cb, src, index, base);
            emit1(cb, 0x0F);
            emit1(cb, 0xB1); /* cmpxchg r/m32, r32 */
            break;
        case 8:
            emit_rex_w_sib(cb, src, index, base);
            emit1(cb, 0x0F);
            emit1(cb, 0xB1); /* cmpxchg r/m64, r64 */
            break;
        default:
            fprintf(stderr, "unsupported cmpxchg access size\n");
            exit(1);
    }
    emit1(cb, (uint8_t)(0x80 | ((src & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_lock_cmpxchg_mem_base_disp32_from_r(CodeBuf *cb, int base, int src, int32_t disp,
                                                     unsigned access_size) {
    /* SIB index=100b encodes "no index" -> [base + disp32]. */
    x86_lock_cmpxchg_mem_base_index_disp32_from_r(cb, base, 4, src, disp, access_size);
}

static void x86_movsxd_r_from_mem_base_index_disp32(CodeBuf *cb, int dst, int base, int index, int32_t disp) {
    emit_rex_w_sib(cb, dst, index, base);
    emit1(cb, 0x63); /* movsxd r64, r/m32 */
    emit1(cb, (uint8_t)(0x80 | ((dst & 7) << 3) | 0x04)); /* mod=10, rm=SIB */
    emit1(cb, (uint8_t)((0u << 6) | ((index & 7) << 3) | (base & 7))); /* scale=1 */
    emit4(cb, (uint32_t)disp);
}

static void x86_test_rr(CodeBuf *cb, int lhs, int rhs) {
    emit_rex_w(cb, rhs, lhs);
    emit1(cb, 0x85); /* test r/m64, r64 */
    emit1(cb, (uint8_t)(0xC0 | ((rhs & 7) << 3) | (lhs & 7)));
}

static void x86_test_rr32(CodeBuf *cb, int lhs, int rhs) {
    emit_rex_32(cb, rhs, lhs);
    emit1(cb, 0x85); /* test r/m32, r32 */
    emit1(cb, (uint8_t)(0xC0 | ((rhs & 7) << 3) | (lhs & 7)));
}

static void x86_jmp_r(CodeBuf *cb, int reg) {
    if (reg >= 8) {
        emit1(cb, 0x41);
    }
    emit1(cb, 0xFF); /* jmp r/m64 */
    emit1(cb, (uint8_t)(0xE0 | (reg & 7))); /* /4, mod=11 */
}

static void x86_call_r(CodeBuf *cb, int reg) {
    if (reg >= 8) {
        emit1(cb, 0x41);
    }
    emit1(cb, 0xFF); /* call r/m64 */
    emit1(cb, (uint8_t)(0xD0 | (reg & 7))); /* /2, mod=11 */
}

static size_t x86_jmp_rel32(CodeBuf *cb) {
    emit1(cb, 0xE9);
    cb_need(cb, 4);
    size_t off = cb->len;
    emit4(cb, 0);
    return off;
}

static size_t x86_jcc_rel32(CodeBuf *cb, uint8_t cc) {
    emit1(cb, 0x0F);
    emit1(cb, cc);
    cb_need(cb, 4);
    size_t off = cb->len;
    emit4(cb, 0);
    return off;
}

static size_t x86_jz_rel32(CodeBuf *cb) {
    return x86_jcc_rel32(cb, 0x84);
}

static size_t x86_jnz_rel32(CodeBuf *cb) {
    return x86_jcc_rel32(cb, 0x85);
}

static size_t x86_jc_rel32(CodeBuf *cb) {
    return x86_jcc_rel32(cb, 0x82);
}

static size_t x86_jnc_rel32(CodeBuf *cb) {
    return x86_jcc_rel32(cb, 0x83);
}

static size_t x86_ja_rel32(CodeBuf *cb) {
    return x86_jcc_rel32(cb, 0x87);
}

static void x86_cmovcc_rr(CodeBuf *cb, int dst, int src, uint8_t cc_low) {
    emit_rex_w(cb, dst, src);
    emit1(cb, 0x0F);
    emit1(cb, (uint8_t)(0x40 | (cc_low & 0x0F))); /* CMOVcc */
    emit1(cb, (uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}

static void x86_cmovcc_rr32(CodeBuf *cb, int dst, int src, uint8_t cc_low) {
    emit_rex_32(cb, dst, src);
    emit1(cb, 0x0F);
    emit1(cb, (uint8_t)(0x40 | (cc_low & 0x0F))); /* CMOVcc */
    emit1(cb, (uint8_t)(0xC0 | ((dst & 7) << 3) | (src & 7)));
}

static void x86_shift_imm(CodeBuf *cb, int reg, unsigned shift_kind, unsigned amount) {
    if (amount == 0) {
        return;
    }
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0xC1); /* shift r/m64, imm8 */
    switch (shift_kind) {
        case 0: /* LSL */
            emit1(cb, (uint8_t)(0xE0 | (reg & 7))); /* /4 */
            break;
        case 1: /* LSR */
            emit1(cb, (uint8_t)(0xE8 | (reg & 7))); /* /5 */
            break;
        case 2: /* ASR */
            emit1(cb, (uint8_t)(0xF8 | (reg & 7))); /* /7 */
            break;
        default:
            fprintf(stderr, "unsupported shift kind\n");
            exit(1);
    }
    emit1(cb, (uint8_t)(amount & 0x3Fu));
}

static void x86_shift_imm32(CodeBuf *cb, int reg, unsigned shift_kind, unsigned amount) {
    if (amount == 0) {
        return;
    }
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0xC1); /* shift r/m32, imm8 */
    switch (shift_kind) {
        case 0: /* LSL */
            emit1(cb, (uint8_t)(0xE0 | (reg & 7))); /* /4 */
            break;
        case 1: /* LSR */
            emit1(cb, (uint8_t)(0xE8 | (reg & 7))); /* /5 */
            break;
        case 2: /* ASR */
            emit1(cb, (uint8_t)(0xF8 | (reg & 7))); /* /7 */
            break;
        default:
            fprintf(stderr, "unsupported shift kind\n");
            exit(1);
    }
    emit1(cb, (uint8_t)(amount & 0x1Fu));
}

static void x86_shift_cl(CodeBuf *cb, int reg, unsigned shift_kind) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0xD3); /* shift/rotate r/m64, cl */
    switch (shift_kind) {
        case 0: /* LSL */
            emit1(cb, (uint8_t)(0xE0 | (reg & 7))); /* /4 */
            break;
        case 1: /* LSR */
            emit1(cb, (uint8_t)(0xE8 | (reg & 7))); /* /5 */
            break;
        case 2: /* ASR */
            emit1(cb, (uint8_t)(0xF8 | (reg & 7))); /* /7 */
            break;
        case 3: /* ROR */
            emit1(cb, (uint8_t)(0xC8 | (reg & 7))); /* /1 */
            break;
        default:
            fprintf(stderr, "unsupported variable shift kind\n");
            exit(1);
    }
}

static void x86_shift_cl32(CodeBuf *cb, int reg, unsigned shift_kind) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0xD3); /* shift/rotate r/m32, cl */
    switch (shift_kind) {
        case 0: /* LSL */
            emit1(cb, (uint8_t)(0xE0 | (reg & 7))); /* /4 */
            break;
        case 1: /* LSR */
            emit1(cb, (uint8_t)(0xE8 | (reg & 7))); /* /5 */
            break;
        case 2: /* ASR */
            emit1(cb, (uint8_t)(0xF8 | (reg & 7))); /* /7 */
            break;
        case 3: /* ROR */
            emit1(cb, (uint8_t)(0xC8 | (reg & 7))); /* /1 */
            break;
        default:
            fprintf(stderr, "unsupported variable shift kind\n");
            exit(1);
    }
}

static void x86_bt_imm8(CodeBuf *cb, int reg, uint8_t bit) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0x0F);
    emit1(cb, 0xBA); /* BT r/m64, imm8 */
    emit1(cb, (uint8_t)(0xE0 | (reg & 7))); /* /4 */
    emit1(cb, bit);
}

static void x86_cqo(CodeBuf *cb) {
    emit1(cb, 0x48);
    emit1(cb, 0x99); /* cqo */
}

static void x86_cdq(CodeBuf *cb) {
    emit1(cb, 0x99); /* cdq */
}

static void x86_div_r(CodeBuf *cb, int reg) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0xF7); /* div r/m64 */
    emit1(cb, (uint8_t)(0xF0 | (reg & 7))); /* /6 */
}

static void x86_idiv_r(CodeBuf *cb, int reg) {
    emit_rex_w(cb, 0, reg);
    emit1(cb, 0xF7); /* idiv r/m64 */
    emit1(cb, (uint8_t)(0xF8 | (reg & 7))); /* /7 */
}

static void x86_div_r32(CodeBuf *cb, int reg) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0xF7); /* div r/m32 */
    emit1(cb, (uint8_t)(0xF0 | (reg & 7))); /* /6 */
}

static void x86_idiv_r32(CodeBuf *cb, int reg) {
    emit_rex_32(cb, 0, reg);
    emit1(cb, 0xF7); /* idiv r/m32 */
    emit1(cb, (uint8_t)(0xF8 | (reg & 7))); /* /7 */
}

static int materialize_shifted_rm(CodeBuf *cb, int x86_rm, unsigned shift, unsigned imm6, size_t pc,
                                  const char *insn_name) {
    if (shift > 2) {
        fprintf(stderr, "unsupported %s shift kind at pc=%zu\n", insn_name, pc);
        exit(1);
    }
    if (imm6 == 0) {
        return x86_rm;
    }

    const int tmp = 10; /* r10 scratch */
    x86_mov_rr(cb, tmp, x86_rm);
    x86_shift_imm(cb, tmp, shift, imm6);
    return tmp;
}

static int materialize_shifted_rm32(CodeBuf *cb, int x86_rm, unsigned shift, unsigned imm6, size_t pc,
                                    const char *insn_name) {
    if (shift > 2) {
        fprintf(stderr, "unsupported %s shift kind at pc=%zu\n", insn_name, pc);
        exit(1);
    }
    if (imm6 > 31u) {
        fprintf(stderr, "unsupported %s shift amount for 32-bit form at pc=%zu\n", insn_name, pc);
        exit(1);
    }
    if (imm6 == 0) {
        return x86_rm;
    }

    const int tmp = 10; /* r10 scratch */
    x86_mov_rr32(cb, tmp, x86_rm);
    x86_shift_imm32(cb, tmp, shift, imm6);
    return tmp;
}

static int materialize_extended_rm(CodeBuf *cb, int x86_rm, unsigned option, unsigned imm3, bool is_32, size_t pc,
                                   const char *insn_name) {
    const int tmp = 10; /* r10 scratch */

    if (imm3 > 4u) {
        fprintf(stderr, "unsupported %s extension shift (must be 0..4) at pc=%zu\n", insn_name, pc);
        exit(1);
    }

    switch (option) {
        case 0: /* UXTB */
            x86_mov_rr32(cb, tmp, x86_rm);
            x86_shift_imm(cb, tmp, 0, 56);
            x86_shift_imm(cb, tmp, 1, 56);
            break;
        case 1: /* UXTH */
            x86_mov_rr32(cb, tmp, x86_rm);
            x86_shift_imm(cb, tmp, 0, 48);
            x86_shift_imm(cb, tmp, 1, 48);
            break;
        case 2: /* UXTW */
            x86_mov_rr32(cb, tmp, x86_rm);
            break;
        case 3: /* UXTX (64-bit) / LSL alias (32-bit) */
            if (is_32) {
                x86_mov_rr32(cb, tmp, x86_rm);
            } else {
                x86_mov_rr(cb, tmp, x86_rm);
            }
            break;
        case 4: /* SXTB */
            x86_mov_rr32(cb, tmp, x86_rm);
            x86_shift_imm(cb, tmp, 0, 56);
            x86_shift_imm(cb, tmp, 2, 56);
            break;
        case 5: /* SXTH */
            x86_mov_rr32(cb, tmp, x86_rm);
            x86_shift_imm(cb, tmp, 0, 48);
            x86_shift_imm(cb, tmp, 2, 48);
            break;
        case 6: /* SXTW */
            x86_mov_rr32(cb, tmp, x86_rm);
            x86_shift_imm(cb, tmp, 0, 32);
            x86_shift_imm(cb, tmp, 2, 32);
            break;
        case 7: /* SXTX (64-bit) / SXTW-ish behavior for 32-bit aliases */
            if (is_32) {
                x86_mov_rr32(cb, tmp, x86_rm);
                x86_shift_imm(cb, tmp, 0, 32);
                x86_shift_imm(cb, tmp, 2, 32);
            } else {
                x86_mov_rr(cb, tmp, x86_rm);
            }
            break;
        default:
            fprintf(stderr, "unsupported %s extension option at pc=%zu\n", insn_name, pc);
            exit(1);
    }

    if (imm3 != 0u) {
        x86_shift_imm(cb, tmp, 0, imm3);
    }
    return tmp;
}

static void x86_ret(CodeBuf *cb) {
    emit1(cb, 0xC3);
}

static int arm_cond_to_x86_cc(unsigned cond) {
    switch (cond) {
        case 0x0: /* EQ */
            return 0x4;
        case 0x1: /* NE */
            return 0x5;
        case 0x2: /* HS/CS */
            return 0x3;
        case 0x3: /* LO/CC */
            return 0x2;
        case 0x4: /* MI */
            return 0x8;
        case 0x5: /* PL */
            return 0x9;
        case 0x6: /* VS */
            return 0x0;
        case 0x7: /* VC */
            return 0x1;
        case 0x8: /* HI */
            return 0x7;
        case 0x9: /* LS */
            return 0x6;
        case 0xA: /* GE */
            return 0xD;
        case 0xB: /* LT */
            return 0xC;
        case 0xC: /* GT */
            return 0xF;
        case 0xD: /* LE */
            return 0xE;
        default:
            return -1;
    }
}

static void emit_guest_mem_bounds_check(CodeBuf *cb, OobPatchVec *oob_patches, int idx_reg, int32_t disp,
                                        uint32_t access_size, size_t pc) {
    if (access_size == 0 || access_size > GUEST_MEM_SIZE) {
        fprintf(stderr, "invalid access size\n");
        exit(1);
    }

    emit_preserve_guest_flags_begin(cb);

    x86_mov_rr(cb, 10, idx_reg); /* r10 = effective offset base */
    if (disp > 0) {
        x86_add_imm32(cb, 10, (uint32_t)disp);
        oobv_push(oob_patches, x86_jc_rel32(cb), (uint64_t)(pc * 4u)); /* detect unsigned wraparound */
    } else if (disp < 0) {
        uint32_t abs_disp = (uint32_t)(-disp);
        x86_sub_imm32(cb, 10, abs_disp);
        oobv_push(oob_patches, x86_jc_rel32(cb), (uint64_t)(pc * 4u)); /* detect unsigned underflow */
    }
    x86_cmp_imm32(cb, 10, GUEST_MEM_SIZE - access_size);
    oobv_push(oob_patches, x86_ja_rel32(cb), (uint64_t)(pc * 4u));

    emit_preserve_guest_flags_end(cb);
}

static int materialize_guest_mem_reg_offset(CodeBuf *cb, OobPatchVec *oob_patches, int x86_rn, int x86_rm,
                                            unsigned option, unsigned s, uint32_t access_size, size_t pc,
                                            const char *insn_name) {
    unsigned sizeshift;
    bool is_signed_extend;

    switch (access_size) {
        case 1:
            sizeshift = 0;
            break;
        case 2:
            sizeshift = 1;
            break;
        case 4:
            sizeshift = 2;
            break;
        case 8:
            sizeshift = 3;
            break;
        default:
            fprintf(stderr, "invalid access size in %s at pc=%zu\n", insn_name, pc);
            exit(1);
    }

    emit_preserve_guest_flags_begin(cb);

    if (x86_rm != 10) {
        x86_mov_rr(cb, 10, x86_rm);
    }

    switch (option) {
        case 0: /* UXTB */
            x86_shift_imm(cb, 10, 0, 56); /* shl */
            x86_shift_imm(cb, 10, 1, 56); /* shr */
            break;
        case 1: /* UXTH */
            x86_shift_imm(cb, 10, 0, 48); /* shl */
            x86_shift_imm(cb, 10, 1, 48); /* shr */
            break;
        case 2: /* UXTW */
            x86_mov_rr32(cb, 10, 10); /* zero-extend Wm */
            break;
        case 3: /* UXTX/LSL */
            break;
        case 4: /* SXTB */
            x86_shift_imm(cb, 10, 0, 56); /* shl */
            x86_shift_imm(cb, 10, 2, 56); /* sar */
            break;
        case 5: /* SXTH */
            x86_shift_imm(cb, 10, 0, 48); /* shl */
            x86_shift_imm(cb, 10, 2, 48); /* sar */
            break;
        case 6: /* SXTW */
            x86_movsxd_rr(cb, 10, 10);
            break;
        case 7: /* SXTX */
            break;
        default:
            fprintf(stderr, "unsupported reg-offset option in %s at pc=%zu\n", insn_name, pc);
            exit(1);
    }

    if (s != 0u && sizeshift != 0u) {
        x86_shift_imm(cb, 10, 0, sizeshift); /* LSL #sizeshift */
    }

    /* r13 = effective byte offset = base + (possibly extended/signed) reg-offset */
    x86_mov_rr(cb, 13, x86_rn);
    x86_add_rr(cb, 13, 10);
    is_signed_extend = option >= 4u;
    if (!is_signed_extend) {
        /* Unsigned offset must not wrap: result >= base. */
        x86_cmp_rr(cb, 13, x86_rn);
        oobv_push(oob_patches, x86_jc_rel32(cb), (uint64_t)(pc * 4u));
    } else {
        /*
         * Signed offset:
         * - if offset >= 0 then result must be >= base
         * - if offset <  0 then result must be <= base
         */
        x86_test_rr(cb, 10, 10); /* sign of effective register offset */
        size_t neg_off = x86_jcc_rel32(cb, 0x88); /* JS */
        size_t join_off;
        x86_cmp_rr(cb, 13, x86_rn);
        oobv_push(oob_patches, x86_jc_rel32(cb), (uint64_t)(pc * 4u));
        join_off = x86_jmp_rel32(cb);
        patch_rel32_at(cb->data, neg_off, cb->len);
        x86_cmp_rr(cb, 13, x86_rn);
        oobv_push(oob_patches, x86_ja_rel32(cb), (uint64_t)(pc * 4u));
        patch_rel32_at(cb->data, join_off, cb->len);
    }
    x86_cmp_imm32(cb, 13, GUEST_MEM_SIZE - access_size);
    oobv_push(oob_patches, x86_ja_rel32(cb), (uint64_t)(pc * 4u));

    emit_preserve_guest_flags_end(cb);
    return 13;
}

static int state_x_offset(unsigned a64_reg) {
    return (int)(offsetof(CPUState, x) + (a64_reg * sizeof(uint64_t)));
}

static int state_v_qword_offset(unsigned vreg, unsigned qword) {
    return (int)(offsetof(CPUState, v) + (((vreg * 2u) + qword) * sizeof(uint64_t)));
}

static void emit_sync_mapped_guest_regs_to_state(CodeBuf *cb) {
    for (unsigned reg = 0; reg < 31; ++reg) {
        int host = map_reg(reg);
        if (host < 0) {
            continue;
        }
        x86_mov_mem_base_disp32_from_r(cb, 3, state_x_offset(reg), host);
    }
}

static void emit_reload_mapped_guest_regs_from_state(CodeBuf *cb, bool include_x0) {
    for (unsigned reg = 0; reg < 31; ++reg) {
        int host = map_reg(reg);
        if (host < 0) {
            continue;
        }
        if (!include_x0 && reg == 0u) {
            continue;
        }
        x86_mov_r_from_mem_base_disp32(cb, host, 3, state_x_offset(reg));
    }
}

static void emit_host_import_callback(CodeBuf *cb, uint8_t callback_id) {
    emit_preserve_guest_flags_begin(cb);

    /* Materialize guest x0..x10 in state so callbacks can read argument registers. */
    emit_sync_mapped_guest_regs_to_state(cb);

    /* SysV ABI: rdi=CPUState*, rsi=callback_id. */
    x86_mov_rr(cb, 7, 3);
    x86_mov_imm64(cb, 6, callback_id);

    /* Align stack to 16 bytes before the call. */
    x86_sub_imm32(cb, 4, 8);
    x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)dbt_runtime_import_callback_dispatch);
    x86_call_r(cb, 10);
    x86_add_imm32(cb, 4, 8);

    /* Preserve callback return value, then restore caller-saved guest mappings. */
    x86_mov_rr(cb, 13, 0);
    emit_reload_mapped_guest_regs_from_state(cb, false);
    x86_mov_rr(cb, 0, 13);

    emit_preserve_guest_flags_end(cb);
}

static void emit_set_state_pc_bytes(CodeBuf *cb, uint64_t pc_bytes) {
    x86_mov_imm64(cb, 10, pc_bytes); /* r10 = next pc */
    x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, pc), 10);
}

static void emit_set_exit_reason(CodeBuf *cb, uint64_t reason) {
    x86_mov_imm64(cb, 10, reason);
    x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, exit_reason), 10);
}

static void emit_writeback_add_signed_imm(CodeBuf *cb, int x86_rn, int32_t simm9) {
    if (simm9 == 0) {
        return;
    }

    emit_preserve_guest_flags_begin(cb);
    if (simm9 > 0) {
        x86_add_imm32(cb, x86_rn, (uint32_t)simm9);
    } else {
        x86_sub_imm32(cb, x86_rn, (uint32_t)(-simm9));
    }
    emit_preserve_guest_flags_end(cb);
}

static int materialize_guest_xreg_read(CodeBuf *cb, unsigned reg, int scratch, size_t pc, const char *insn_name) {
    if (reg >= 31u) {
        fprintf(stderr, "SP/XZR form of %s unsupported at pc=%zu\n", insn_name, pc);
        exit(1);
    }

    int host = map_reg(reg);
    if (host >= 0) {
        return host;
    }

    x86_mov_r_from_mem_base_disp32(cb, scratch, 3, state_x_offset(reg));
    return scratch;
}

static int materialize_guest_xreg_or_zr_read(CodeBuf *cb, unsigned reg, int scratch, size_t pc, const char *insn_name) {
    if (reg == 31u) {
        x86_mov_imm64(cb, scratch, 0);
        return scratch;
    }
    return materialize_guest_xreg_read(cb, reg, scratch, pc, insn_name);
}

static int materialize_guest_xreg_or_sp_read(CodeBuf *cb, unsigned reg, int scratch, size_t pc, const char *insn_name) {
    if (reg == 31u) {
        x86_mov_r_from_mem_base_disp32(cb, scratch, 3, (int32_t)offsetof(CPUState, sp));
        return scratch;
    }
    return materialize_guest_xreg_read(cb, reg, scratch, pc, insn_name);
}

static void writeback_guest_xreg(CodeBuf *cb, unsigned reg, int src, size_t pc, const char *insn_name) {
    if (reg >= 31u) {
        fprintf(stderr, "SP/XZR destination form of %s unsupported at pc=%zu\n", insn_name, pc);
        exit(1);
    }

    int host = map_reg(reg);
    if (host >= 0) {
        if (host != src) {
            x86_mov_rr(cb, host, src);
        }
        return;
    }

    x86_mov_mem_base_disp32_from_r(cb, 3, state_x_offset(reg), src);
}

static void writeback_guest_xreg_or_sp(CodeBuf *cb, unsigned reg, int src, size_t pc, const char *insn_name) {
    if (reg == 31u) {
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, sp), src);
        return;
    }
    writeback_guest_xreg(cb, reg, src, pc, insn_name);
}

static void writeback_guest_xreg_unless_zr(CodeBuf *cb, unsigned reg, int src, size_t pc, const char *insn_name) {
    if (reg == 31u) {
        return;
    }
    writeback_guest_xreg(cb, reg, src, pc, insn_name);
}

static void emit_writeback_add_signed_imm_guest(CodeBuf *cb, unsigned rn, int x86_rn, int32_t simm9, size_t pc,
                                                const char *insn_name) {
    emit_writeback_add_signed_imm(cb, x86_rn, simm9);
    if (rn == 31u || map_reg(rn) < 0) {
        writeback_guest_xreg_or_sp(cb, rn, x86_rn, pc, insn_name);
    }
}

static void emit_zero_extend_reg_for_size(CodeBuf *cb, int reg, uint32_t access_size) {
    switch (access_size) {
        case 1:
            x86_shift_imm(cb, reg, 0, 56); /* shl */
            x86_shift_imm(cb, reg, 1, 56); /* shr */
            break;
        case 2:
            x86_shift_imm(cb, reg, 0, 48); /* shl */
            x86_shift_imm(cb, reg, 1, 48); /* shr */
            break;
        case 4:
            x86_shift_imm(cb, reg, 0, 32); /* shl */
            x86_shift_imm(cb, reg, 1, 32); /* shr */
            break;
        case 8:
            break;
        default:
            fprintf(stderr, "invalid access size for zero-extend helper\n");
            exit(1);
    }
}

static void emit_sign_extend_reg_for_size(CodeBuf *cb, int reg, uint32_t access_size) {
    switch (access_size) {
        case 1:
            x86_shift_imm(cb, reg, 0, 56); /* shl */
            x86_shift_imm(cb, reg, 2, 56); /* sar */
            break;
        case 2:
            x86_shift_imm(cb, reg, 0, 48); /* shl */
            x86_shift_imm(cb, reg, 2, 48); /* sar */
            break;
        case 4:
            x86_shift_imm(cb, reg, 0, 32); /* shl */
            x86_shift_imm(cb, reg, 2, 32); /* sar */
            break;
        case 8:
            break;
        default:
            fprintf(stderr, "invalid access size for sign-extend helper\n");
            exit(1);
    }
}

static void emit_preserve_guest_flags_begin(CodeBuf *cb) {
    emit_capture_rflags_to_reg(cb, 12); /* r12 keeps old guest NZCV state */
}

static void emit_preserve_guest_flags_end(CodeBuf *cb) {
    emit_load_rflags_from_reg(cb, 12);
}

static void emit_set_nzcv_imm4(CodeBuf *cb, unsigned nzcv_imm4) {
    uint32_t nzcv = (uint32_t)(nzcv_imm4 & 0xFu) << 28;
    uint64_t rflags = nzcv_to_rflags(nzcv);

    x86_mov_imm64(cb, 10, rflags);
    emit_load_rflags_from_reg(cb, 10);
}

static void emit_fp_compare_set_nzcv_s(CodeBuf *cb, unsigned rn, unsigned rm) {
    int32_t rn_disp = state_v_qword_offset(rn, 0);
    int32_t rm_disp = state_v_qword_offset(rm, 0);
    const uint32_t exp_mask = 0x7F800000u;
    const uint32_t mant_mask = 0x007FFFFFu;
    const uint32_t sign_mask = 0x80000000u;
    size_t to_check_b_nan;
    size_t to_unordered_a;
    size_t to_ordered_b;
    size_t to_unordered_b;
    size_t to_nonzero_a;
    size_t to_nonzero_b;
    size_t to_done_zeroeq;
    size_t to_a_nonneg;
    size_t to_a_done;
    size_t to_b_nonneg;
    size_t to_b_done;
    size_t to_less;
    size_t to_greater;
    size_t to_done_equal;
    size_t to_done_less;
    size_t to_done_greater;
    size_t to_done_unordered;
    size_t done_off;

    /* r10 = bits(Sn), r13 = bits(Sm) */
    x86_mov_r32_from_mem_base_disp32(cb, 10, 3, rn_disp);
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rm_disp);

    /* NaN check for Sn */
    x86_mov_rr32(cb, 12, 10);
    x86_mov_imm64(cb, 13, exp_mask);
    x86_and_rr32(cb, 12, 13);
    x86_cmp_rr32(cb, 12, 13);
    to_check_b_nan = x86_jnz_rel32(cb);
    x86_mov_rr32(cb, 12, 10);
    x86_mov_imm64(cb, 13, mant_mask);
    x86_and_rr32(cb, 12, 13);
    x86_cmp_imm32_32(cb, 12, 0);
    to_unordered_a = x86_jnz_rel32(cb);

    /* NaN check for Sm */
    patch_rel32_at(cb->data, to_check_b_nan, cb->len);
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rm_disp);
    x86_mov_rr32(cb, 12, 13);
    x86_mov_imm64(cb, 10, exp_mask);
    x86_and_rr32(cb, 12, 10);
    x86_cmp_rr32(cb, 12, 10);
    to_ordered_b = x86_jnz_rel32(cb);
    x86_mov_rr32(cb, 12, 13);
    x86_mov_imm64(cb, 10, mant_mask);
    x86_and_rr32(cb, 12, 10);
    x86_cmp_imm32_32(cb, 12, 0);
    to_unordered_b = x86_jnz_rel32(cb);

    /* Ordered path */
    patch_rel32_at(cb->data, to_ordered_b, cb->len);
    x86_mov_r32_from_mem_base_disp32(cb, 10, 3, rn_disp);
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rm_disp);

    /* +0.0 and -0.0 compare equal. */
    x86_mov_rr32(cb, 12, 10);
    x86_shift_imm32(cb, 12, 0, 1);
    x86_cmp_imm32_32(cb, 12, 0);
    to_nonzero_a = x86_jnz_rel32(cb);
    x86_mov_rr32(cb, 12, 13);
    x86_shift_imm32(cb, 12, 0, 1);
    x86_cmp_imm32_32(cb, 12, 0);
    to_nonzero_b = x86_jnz_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x6u); /* equal */
    to_done_zeroeq = x86_jmp_rel32(cb);

    /* Monotonic key transform for IEEE754 (excluding NaN/zero handled above). */
    patch_rel32_at(cb->data, to_nonzero_a, cb->len);
    patch_rel32_at(cb->data, to_nonzero_b, cb->len);
    x86_mov_rr32(cb, 12, 10);
    x86_test_rr32(cb, 12, 12);
    to_a_nonneg = x86_jcc_rel32(cb, 0x89); /* JNS */
    x86_not_r32(cb, 10);
    to_a_done = x86_jmp_rel32(cb);
    patch_rel32_at(cb->data, to_a_nonneg, cb->len);
    x86_mov_imm64(cb, 12, sign_mask);
    x86_xor_rr32(cb, 10, 12);
    patch_rel32_at(cb->data, to_a_done, cb->len);

    x86_mov_rr32(cb, 12, 13);
    x86_test_rr32(cb, 12, 12);
    to_b_nonneg = x86_jcc_rel32(cb, 0x89); /* JNS */
    x86_not_r32(cb, 13);
    to_b_done = x86_jmp_rel32(cb);
    patch_rel32_at(cb->data, to_b_nonneg, cb->len);
    x86_mov_imm64(cb, 12, sign_mask);
    x86_xor_rr32(cb, 13, 12);
    patch_rel32_at(cb->data, to_b_done, cb->len);

    x86_cmp_rr32(cb, 10, 13);
    to_less = x86_jc_rel32(cb);
    to_greater = x86_ja_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x6u); /* equal */
    to_done_equal = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_less, cb->len);
    emit_set_nzcv_imm4(cb, 0x8u); /* less */
    to_done_less = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_greater, cb->len);
    emit_set_nzcv_imm4(cb, 0x2u); /* greater */
    to_done_greater = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_unordered_a, cb->len);
    patch_rel32_at(cb->data, to_unordered_b, cb->len);
    emit_set_nzcv_imm4(cb, 0x3u); /* unordered */
    to_done_unordered = x86_jmp_rel32(cb);

    done_off = cb->len;
    patch_rel32_at(cb->data, to_done_zeroeq, done_off);
    patch_rel32_at(cb->data, to_done_equal, done_off);
    patch_rel32_at(cb->data, to_done_less, done_off);
    patch_rel32_at(cb->data, to_done_greater, done_off);
    patch_rel32_at(cb->data, to_done_unordered, done_off);
}

static void emit_fp_compare_set_nzcv_d(CodeBuf *cb, unsigned rn, unsigned rm) {
    int32_t rn_disp = state_v_qword_offset(rn, 0);
    int32_t rm_disp = state_v_qword_offset(rm, 0);
    const uint64_t exp_mask = 0x7FF0000000000000ull;
    const uint64_t mant_mask = 0x000FFFFFFFFFFFFFull;
    const uint64_t sign_mask = 0x8000000000000000ull;
    size_t to_check_b_nan;
    size_t to_unordered_a;
    size_t to_ordered_b;
    size_t to_unordered_b;
    size_t to_nonzero_a;
    size_t to_nonzero_b;
    size_t to_done_zeroeq;
    size_t to_a_nonneg;
    size_t to_a_done;
    size_t to_b_nonneg;
    size_t to_b_done;
    size_t to_less;
    size_t to_greater;
    size_t to_done_equal;
    size_t to_done_less;
    size_t to_done_greater;
    size_t to_done_unordered;
    size_t done_off;

    /* r10 = bits(Dn), r13 = bits(Dm) */
    x86_mov_r_from_mem_base_disp32(cb, 10, 3, rn_disp);
    x86_mov_r_from_mem_base_disp32(cb, 13, 3, rm_disp);

    /* NaN check for Dn */
    x86_mov_rr(cb, 12, 10);
    x86_mov_imm64(cb, 13, exp_mask);
    x86_and_rr(cb, 12, 13);
    x86_cmp_rr(cb, 12, 13);
    to_check_b_nan = x86_jnz_rel32(cb);
    x86_mov_rr(cb, 12, 10);
    x86_mov_imm64(cb, 13, mant_mask);
    x86_and_rr(cb, 12, 13);
    x86_cmp_imm32(cb, 12, 0);
    to_unordered_a = x86_jnz_rel32(cb);

    /* NaN check for Dm */
    patch_rel32_at(cb->data, to_check_b_nan, cb->len);
    x86_mov_r_from_mem_base_disp32(cb, 13, 3, rm_disp);
    x86_mov_rr(cb, 12, 13);
    x86_mov_imm64(cb, 10, exp_mask);
    x86_and_rr(cb, 12, 10);
    x86_cmp_rr(cb, 12, 10);
    to_ordered_b = x86_jnz_rel32(cb);
    x86_mov_rr(cb, 12, 13);
    x86_mov_imm64(cb, 10, mant_mask);
    x86_and_rr(cb, 12, 10);
    x86_cmp_imm32(cb, 12, 0);
    to_unordered_b = x86_jnz_rel32(cb);

    /* Ordered path */
    patch_rel32_at(cb->data, to_ordered_b, cb->len);
    x86_mov_r_from_mem_base_disp32(cb, 10, 3, rn_disp);
    x86_mov_r_from_mem_base_disp32(cb, 13, 3, rm_disp);

    /* +0.0 and -0.0 compare equal. */
    x86_mov_rr(cb, 12, 10);
    x86_shift_imm(cb, 12, 0, 1);
    x86_cmp_imm32(cb, 12, 0);
    to_nonzero_a = x86_jnz_rel32(cb);
    x86_mov_rr(cb, 12, 13);
    x86_shift_imm(cb, 12, 0, 1);
    x86_cmp_imm32(cb, 12, 0);
    to_nonzero_b = x86_jnz_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x6u); /* equal */
    to_done_zeroeq = x86_jmp_rel32(cb);

    /* Monotonic key transform for IEEE754 (excluding NaN/zero handled above). */
    patch_rel32_at(cb->data, to_nonzero_a, cb->len);
    patch_rel32_at(cb->data, to_nonzero_b, cb->len);
    x86_mov_rr(cb, 12, 10);
    x86_test_rr(cb, 12, 12);
    to_a_nonneg = x86_jcc_rel32(cb, 0x89); /* JNS */
    x86_not_r(cb, 10);
    to_a_done = x86_jmp_rel32(cb);
    patch_rel32_at(cb->data, to_a_nonneg, cb->len);
    x86_mov_imm64(cb, 12, sign_mask);
    x86_xor_rr(cb, 10, 12);
    patch_rel32_at(cb->data, to_a_done, cb->len);

    x86_mov_rr(cb, 12, 13);
    x86_test_rr(cb, 12, 12);
    to_b_nonneg = x86_jcc_rel32(cb, 0x89); /* JNS */
    x86_not_r(cb, 13);
    to_b_done = x86_jmp_rel32(cb);
    patch_rel32_at(cb->data, to_b_nonneg, cb->len);
    x86_mov_imm64(cb, 12, sign_mask);
    x86_xor_rr(cb, 13, 12);
    patch_rel32_at(cb->data, to_b_done, cb->len);

    x86_cmp_rr(cb, 10, 13);
    to_less = x86_jc_rel32(cb);
    to_greater = x86_ja_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x6u); /* equal */
    to_done_equal = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_less, cb->len);
    emit_set_nzcv_imm4(cb, 0x8u); /* less */
    to_done_less = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_greater, cb->len);
    emit_set_nzcv_imm4(cb, 0x2u); /* greater */
    to_done_greater = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_unordered_a, cb->len);
    patch_rel32_at(cb->data, to_unordered_b, cb->len);
    emit_set_nzcv_imm4(cb, 0x3u); /* unordered */
    to_done_unordered = x86_jmp_rel32(cb);

    done_off = cb->len;
    patch_rel32_at(cb->data, to_done_zeroeq, done_off);
    patch_rel32_at(cb->data, to_done_equal, done_off);
    patch_rel32_at(cb->data, to_done_less, done_off);
    patch_rel32_at(cb->data, to_done_greater, done_off);
    patch_rel32_at(cb->data, to_done_unordered, done_off);
}

static void emit_fp_compare_set_nzcv(CodeBuf *cb, unsigned rn, unsigned rm, bool is_double) {
    if (is_double) {
        emit_fp_compare_set_nzcv_d(cb, rn, rm);
    } else {
        emit_fp_compare_set_nzcv_s(cb, rn, rm);
    }
}

static void emit_fp_compare_imm0_set_nzcv_s(CodeBuf *cb, unsigned rn) {
    int32_t rn_disp = state_v_qword_offset(rn, 0);
    const uint32_t exp_mask = 0x7F800000u;
    const uint32_t mant_mask = 0x007FFFFFu;
    const uint32_t sign_mask = 0x80000000u;
    size_t to_not_nan;
    size_t to_not_zero;
    size_t to_positive;
    size_t done_off;
    size_t done_less;
    size_t done_greater;
    size_t done_unordered;

    x86_mov_r32_from_mem_base_disp32(cb, 10, 3, rn_disp);

    /* NaN -> unordered */
    x86_mov_rr32(cb, 12, 10);
    x86_mov_imm64(cb, 13, exp_mask);
    x86_and_rr32(cb, 12, 13);
    x86_cmp_rr32(cb, 12, 13);
    to_not_nan = x86_jnz_rel32(cb);
    x86_mov_rr32(cb, 12, 10);
    x86_mov_imm64(cb, 13, mant_mask);
    x86_and_rr32(cb, 12, 13);
    x86_cmp_imm32_32(cb, 12, 0);
    done_unordered = x86_jnz_rel32(cb);

    patch_rel32_at(cb->data, to_not_nan, cb->len);

    /* +/-0 compare equal to 0 */
    x86_mov_rr32(cb, 12, 10);
    x86_shift_imm32(cb, 12, 0, 1);
    x86_cmp_imm32_32(cb, 12, 0);
    to_not_zero = x86_jnz_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x6u); /* equal */
    done_off = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_not_zero, cb->len);
    x86_mov_imm64(cb, 12, sign_mask);
    x86_and_rr32(cb, 10, 12);
    x86_cmp_imm32_32(cb, 10, 0);
    to_positive = x86_jz_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x8u); /* less */
    done_less = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_positive, cb->len);
    emit_set_nzcv_imm4(cb, 0x2u); /* greater */
    done_greater = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, done_unordered, cb->len);
    emit_set_nzcv_imm4(cb, 0x3u); /* unordered */

    patch_rel32_at(cb->data, done_less, cb->len);
    patch_rel32_at(cb->data, done_greater, cb->len);
    patch_rel32_at(cb->data, done_off, cb->len);
}

static void emit_fp_compare_imm0_set_nzcv_d(CodeBuf *cb, unsigned rn) {
    int32_t rn_disp = state_v_qword_offset(rn, 0);
    const uint64_t exp_mask = 0x7FF0000000000000ull;
    const uint64_t mant_mask = 0x000FFFFFFFFFFFFFull;
    const uint64_t sign_mask = 0x8000000000000000ull;
    size_t to_not_nan;
    size_t to_not_zero;
    size_t to_positive;
    size_t done_off;
    size_t done_less;
    size_t done_greater;
    size_t done_unordered;

    x86_mov_r_from_mem_base_disp32(cb, 10, 3, rn_disp);

    /* NaN -> unordered */
    x86_mov_rr(cb, 12, 10);
    x86_mov_imm64(cb, 13, exp_mask);
    x86_and_rr(cb, 12, 13);
    x86_cmp_rr(cb, 12, 13);
    to_not_nan = x86_jnz_rel32(cb);
    x86_mov_rr(cb, 12, 10);
    x86_mov_imm64(cb, 13, mant_mask);
    x86_and_rr(cb, 12, 13);
    x86_cmp_imm32(cb, 12, 0);
    done_unordered = x86_jnz_rel32(cb);

    patch_rel32_at(cb->data, to_not_nan, cb->len);

    /* +/-0 compare equal to 0 */
    x86_mov_rr(cb, 12, 10);
    x86_shift_imm(cb, 12, 0, 1);
    x86_cmp_imm32(cb, 12, 0);
    to_not_zero = x86_jnz_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x6u); /* equal */
    done_off = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_not_zero, cb->len);
    x86_mov_imm64(cb, 12, sign_mask);
    x86_and_rr(cb, 10, 12);
    x86_cmp_imm32(cb, 10, 0);
    to_positive = x86_jz_rel32(cb);
    emit_set_nzcv_imm4(cb, 0x8u); /* less */
    done_less = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_positive, cb->len);
    emit_set_nzcv_imm4(cb, 0x2u); /* greater */
    done_greater = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, done_unordered, cb->len);
    emit_set_nzcv_imm4(cb, 0x3u); /* unordered */

    patch_rel32_at(cb->data, done_less, cb->len);
    patch_rel32_at(cb->data, done_greater, cb->len);
    patch_rel32_at(cb->data, done_off, cb->len);
}

static void emit_fp_compare_imm0_set_nzcv(CodeBuf *cb, unsigned rn, bool is_double) {
    if (is_double) {
        emit_fp_compare_imm0_set_nzcv_d(cb, rn);
    } else {
        emit_fp_compare_imm0_set_nzcv_s(cb, rn);
    }
}

/*
 * Emit one SQRDMLAH 32-bit lane:
 *   Rd_lane = sat32(Rd_lane + sat32(round((2 * Rn_lane * Rm_lane) / 2^32)))
 */
static void emit_sqrdmlah_lane32(CodeBuf *cb, unsigned rd, unsigned rn, unsigned rm, unsigned qword, unsigned lane) {
    int32_t rd_disp = state_v_qword_offset(rd, qword) + (int32_t)(lane * 4u);
    int32_t rn_disp = state_v_qword_offset(rn, qword) + (int32_t)(lane * 4u);
    int32_t rm_disp = state_v_qword_offset(rm, qword) + (int32_t)(lane * 4u);
    const uint64_t prod_sat = 0x4000000000000000ull;
    const uint64_t round_const = 0x0000000080000000ull;
    const uint64_t i32_max_u64 = 0x000000007FFFFFFFull;
    const uint64_t i32_min_u64 = 0xFFFFFFFF80000000ull;
    size_t to_normal_sqrdmulh;
    size_t to_after_sqrdmulh;
    size_t to_check_low_sat;
    size_t to_store;
    size_t to_store_after_low_check;

    /* r10 = signext(Rn_lane), r13 = signext(Rm_lane) */
    x86_mov_r32_from_mem_base_disp32(cb, 10, 3, rn_disp);
    x86_movsxd_rr(cb, 10, 10);
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rm_disp);
    x86_movsxd_rr(cb, 13, 13);

    /* r10 = Rn_lane * Rm_lane (signed 64-bit) */
    x86_imul_rr(cb, 10, 13);

    /*
     * Handle the only overflow case for doubling: product == 2^62
     * (i.e. INT32_MIN * INT32_MIN), which maps to saturated INT32_MAX.
     */
    x86_mov_imm64(cb, 13, prod_sat);
    x86_cmp_rr(cb, 10, 13);
    to_normal_sqrdmulh = x86_jnz_rel32(cb);
    x86_mov_imm64(cb, 10, i32_max_u64);
    to_after_sqrdmulh = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_normal_sqrdmulh, cb->len);
    x86_add_rr(cb, 10, 10);               /* 2 * product */
    x86_mov_imm64(cb, 13, round_const);   /* + 2^31 for rounding */
    x86_add_rr(cb, 10, 13);
    x86_shift_imm(cb, 10, 2, 32);         /* arithmetic >> 32 */
    patch_rel32_at(cb->data, to_after_sqrdmulh, cb->len);

    /* r10 += signext(Rd_lane) */
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rd_disp);
    x86_movsxd_rr(cb, 13, 13);
    x86_add_rr(cb, 10, 13);

    /* Saturate to signed 32-bit range. */
    x86_mov_imm64(cb, 13, i32_max_u64);
    x86_cmp_rr(cb, 10, 13);
    to_check_low_sat = x86_jcc_rel32(cb, 0x8E); /* JLE */
    x86_mov_rr(cb, 10, 13);
    to_store = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_check_low_sat, cb->len);
    x86_mov_imm64(cb, 13, i32_min_u64);
    x86_cmp_rr(cb, 10, 13);
    to_store_after_low_check = x86_jcc_rel32(cb, 0x8D); /* JGE */
    x86_mov_rr(cb, 10, 13);
    patch_rel32_at(cb->data, to_store_after_low_check, cb->len);
    patch_rel32_at(cb->data, to_store, cb->len);

    /* Store saturated 32-bit lane back to Rd. */
    x86_mov_mem_base_disp32_from_r32(cb, 3, 10, rd_disp);
}

/*
 * Emit one SQRDMLSH 32-bit lane:
 *   Rd_lane = sat32(Rd_lane + sat32(round((-2 * Rn_lane * Rm_lane) / 2^32)))
 */
static void emit_sqrdmlsh_lane32(CodeBuf *cb, unsigned rd, unsigned rn, unsigned rm, unsigned qword, unsigned lane) {
    int32_t rd_disp = state_v_qword_offset(rd, qword) + (int32_t)(lane * 4u);
    int32_t rn_disp = state_v_qword_offset(rn, qword) + (int32_t)(lane * 4u);
    int32_t rm_disp = state_v_qword_offset(rm, qword) + (int32_t)(lane * 4u);
    const uint64_t prod_sat = 0x4000000000000000ull;
    const uint64_t round_const = 0x0000000080000000ull;
    const uint64_t i32_max_u64 = 0x000000007FFFFFFFull;
    const uint64_t i32_min_u64 = 0xFFFFFFFF80000000ull;
    size_t to_normal_sqrdmulh;
    size_t to_after_sqrdmulh;
    size_t to_no_tie_adjust;
    size_t to_check_low_sat;
    size_t to_store;
    size_t to_store_after_low_check;

    /* r10 = signext(Rn_lane), r13 = signext(Rm_lane) */
    x86_mov_r32_from_mem_base_disp32(cb, 10, 3, rn_disp);
    x86_movsxd_rr(cb, 10, 10);
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rm_disp);
    x86_movsxd_rr(cb, 13, 13);

    /* r10 = Rn_lane * Rm_lane (signed 64-bit) */
    x86_imul_rr(cb, 10, 13);

    /*
     * Handle the only overflow case for doubling: product == 2^62
     * (i.e. INT32_MIN * INT32_MIN), which maps to INT32_MIN for the -S form.
     */
    x86_mov_imm64(cb, 13, prod_sat);
    x86_cmp_rr(cb, 10, 13);
    to_normal_sqrdmulh = x86_jnz_rel32(cb);
    x86_mov_imm64(cb, 10, i32_min_u64);
    to_after_sqrdmulh = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_normal_sqrdmulh, cb->len);

    /* r10 = 2 * product */
    x86_add_rr(cb, 10, 10);

    /*
     * Compute rounded high-half for negative doubled product.
     * For RShr rounding, -(RShr(y)) needs +1 adjustment when low32(y)==0x80000000.
     */
    x86_mov_rr32(cb, 12, 10);            /* keep low32(2*product) */
    x86_mov_imm64(cb, 13, round_const);  /* + 2^31 for rounding */
    x86_add_rr(cb, 10, 13);
    x86_shift_imm(cb, 10, 2, 32); /* arithmetic >> 32 */
    x86_mov_imm64(cb, 13, 0);
    x86_sub_rr(cb, 13, 10); /* r13 = -r10 */
    x86_mov_rr(cb, 10, 13);

    x86_cmp_imm32_32(cb, 12, 0x80000000u);
    to_no_tie_adjust = x86_jnz_rel32(cb);
    x86_add_imm32(cb, 10, 1);
    patch_rel32_at(cb->data, to_no_tie_adjust, cb->len);

    patch_rel32_at(cb->data, to_after_sqrdmulh, cb->len);

    /* r10 += signext(Rd_lane) */
    x86_mov_r32_from_mem_base_disp32(cb, 13, 3, rd_disp);
    x86_movsxd_rr(cb, 13, 13);
    x86_add_rr(cb, 10, 13);

    /* Saturate to signed 32-bit range. */
    x86_mov_imm64(cb, 13, i32_max_u64);
    x86_cmp_rr(cb, 10, 13);
    to_check_low_sat = x86_jcc_rel32(cb, 0x8E); /* JLE */
    x86_mov_rr(cb, 10, 13);
    to_store = x86_jmp_rel32(cb);

    patch_rel32_at(cb->data, to_check_low_sat, cb->len);
    x86_mov_imm64(cb, 13, i32_min_u64);
    x86_cmp_rr(cb, 10, 13);
    to_store_after_low_check = x86_jcc_rel32(cb, 0x8D); /* JGE */
    x86_mov_rr(cb, 10, 13);
    patch_rel32_at(cb->data, to_store_after_low_check, cb->len);
    patch_rel32_at(cb->data, to_store, cb->len);

    /* Store saturated 32-bit lane back to Rd. */
    x86_mov_mem_base_disp32_from_r32(cb, 3, 10, rd_disp);
}

static void emit_restore_rflags(CodeBuf *cb) {
    x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, rflags));
    emit_load_rflags_from_reg(cb, 10);
}

static void emit_save_rflags(CodeBuf *cb) {
    emit_capture_rflags_to_reg(cb, 10);
    x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, rflags), 10);
}

static void emit_state_prologue(CodeBuf *cb) {
    /* JIT entry ABI: rdi = CPUState*. Keep state ptr in rbx across the block. */
    x86_push_r(cb, 3);  /* save caller rbx */
    x86_push_r(cb, 5);  /* save caller rbp (mapped guest reg) */
    x86_push_r(cb, 12); /* save caller r12 (used for guest flag preservation) */
    x86_push_r(cb, 13); /* save caller r13 (secondary scratch) */
    x86_push_r(cb, 14); /* save caller r14 (mapped guest reg) */
    x86_push_r(cb, 15); /* save caller r15 (mapped guest reg) */
    x86_mov_rr(cb, 3, 7); /* rbx = CPUState* */
    x86_mov_rr(cb, 10, 3); /* r10 = CPUState* for register loads */

    for (unsigned reg = 0; reg < 31; ++reg) {
        int host = map_reg(reg);
        if (host < 0) {
            continue;
        }
        x86_mov_r_from_mem_base_disp32(cb, host, 10, state_x_offset(reg));
    }
}

static void emit_state_epilogue(CodeBuf *cb) {
    emit_save_rflags(cb);
    x86_mov_rr(cb, 10, 3); /* r10 = CPUState* */

    for (unsigned reg = 0; reg < 31; ++reg) {
        int host = map_reg(reg);
        if (host < 0) {
            continue;
        }
        x86_mov_mem_base_disp32_from_r(cb, 10, state_x_offset(reg), host);
    }
    x86_pop_r(cb, 15); /* restore caller r15 */
    x86_pop_r(cb, 14); /* restore caller r14 */
    x86_pop_r(cb, 13); /* restore caller r13 */
    x86_pop_r(cb, 12); /* restore caller r12 */
    x86_pop_r(cb, 5); /* restore caller rbp */
    x86_pop_r(cb, 3); /* restore caller rbx */
    x86_ret(cb);
}

static void translate_one(CodeBuf *cb, PatchVec *patches, OobPatchVec *oob_patches,
                          UnsupportedPatchVec *unsupported_patches, OffPatchVec *dispatch_patches, uint32_t insn,
                          size_t pc, const uint8_t *guest_mem, size_t n_insn, const uint64_t *entry_targets,
                          const uint64_t *entry_versions) {
    /* NOP */
    if (insn == 0xD503201Fu) {
        return;
    }

    /*
     * HINT-space instructions (including common BTI/PAC/AUT hint encodings)
     * are treated as no-ops in this PoC.
     */
    if ((insn & 0xFFFFF01Fu) == 0xD503201Fu) {
        return;
    }

    /*
     * TinyDBT pseudo-op for ELF import callbacks:
     * HLT #imm16 where imm16 high byte is 0xA5 and low byte is callback id.
     */
    if ((insn & 0xFFE0001Fu) == 0xD4400000u) {
        uint16_t imm16 = (uint16_t)((insn >> 5) & 0xFFFFu);
        if ((imm16 & 0xFF00u) == 0xA500u) {
            emit_host_import_callback(cb, (uint8_t)(imm16 & 0xFFu));
            return;
        }
    }

    /*
     * MRS Xt, <sysreg> (system register read).
     * PoC policy: materialize zero for now.
     */
    if ((insn & 0xFFE00000u) == 0xD5200000u) {
        unsigned rt = insn & 0x1Fu;
        int x86_rt = map_reg(rt);
        if (rt != 31u) {
            if (x86_rt >= 0) {
                x86_mov_imm64(cb, x86_rt, 0);
            } else {
                x86_mov_imm64(cb, 10, 0);
                writeback_guest_xreg(cb, rt, 10, pc, "MRS");
            }
        }
        return;
    }

    /* ADR/ADRP Xd, <label> */
    if ((insn & 0x1F000000u) == 0x10000000u) {
        unsigned rd = insn & 0x1Fu;
        uint32_t immlo = (insn >> 29) & 0x3u;
        uint32_t immhi = (insn >> 5) & 0x7FFFFu;
        int32_t imm21 = sign_extend32((immhi << 2) | immlo, 21);
        int x86_rd = map_reg(rd);
        int64_t pc_bytes = (int64_t)(pc * 4u);
        int64_t value = 0;

        if (insn & 0x80000000u) { /* ADRP */
            value = (pc_bytes & ~0xFFFll) + ((int64_t)imm21 << 12);
        } else { /* ADR */
            value = pc_bytes + imm21;
        }

        if (rd == 31u) {
            return; /* write-discard to XZR */
        }
        if (x86_rd >= 0) {
            x86_mov_imm64(cb, x86_rd, (uint64_t)value);
        } else {
            x86_mov_imm64(cb, 10, (uint64_t)value);
            writeback_guest_xreg(cb, rd, 10, pc, "ADR/ADRP");
        }
        return;
    }

    /* LDAXRB/LDAXRH/LDAXR Wt/Xt, [Xn|SP] */
    if ((insn & 0x3FE0FC00u) == 0x0840FC00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        uint32_t access_size = 1u << size;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDAXR");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        switch (size) {
            case 0:
                x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 1:
                x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 2:
                x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 3:
                x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            default:
                fprintf(stderr, "invalid LDAXR size at pc=%zu\n", pc);
                exit(1);
        }
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDAXR");
        }

        /* Set local exclusive monitor metadata. */
        x86_lea_r_from_base_index_disp32(cb, 13, 10, x86_rn, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_addr), 13);
        x86_mov_imm64(cb, 13, access_size);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_size), 13);
        x86_mov_imm64(cb, 13, 1);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_valid), 13);
        return;
    }

    /* LDXRB/LDXRH/LDXR Wt/Xt, [Xn|SP] */
    if ((insn & 0x3FE0FC00u) == 0x08407C00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        uint32_t access_size = 1u << size;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDXR");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        switch (size) {
            case 0:
                x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 1:
                x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 2:
                x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 3:
                x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            default:
                fprintf(stderr, "invalid LDXR size at pc=%zu\n", pc);
                exit(1);
        }
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDXR");
        }

        /* Set local exclusive monitor metadata. */
        x86_lea_r_from_base_index_disp32(cb, 13, 10, x86_rn, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_addr), 13);
        x86_mov_imm64(cb, 13, access_size);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_size), 13);
        x86_mov_imm64(cb, 13, 1);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_valid), 13);
        return;
    }

    /* STLXRB/STLXRH/STLXR Ws, Wt/Xt, [Xn|SP] */
    if ((insn & 0x3FE0FC00u) == 0x0800FC00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rs = (insn >> 16) & 0x1Fu; /* status register (Ws) */
        unsigned rt = insn & 0x1Fu;         /* data register */
        unsigned rn = (insn >> 5) & 0x1Fu;  /* address base */
        int x86_rs = map_reg(rs);
        int x86_rn;
        int x86_src;
        uint32_t access_size = 1u << size;

        emit_preserve_guest_flags_begin(cb);

        /* r13 = effective host address (guest_mem + base). */
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "STLXR");
        x86_mov_imm64(cb, 13, (uint64_t)(uintptr_t)guest_mem);
        x86_lea_r_from_base_index_disp32(cb, 13, 13, x86_rn, 0);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, excl_valid));
        x86_cmp_imm32(cb, 10, 1);
        size_t to_fail_valid = x86_jnz_rel32(cb);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, excl_size));
        x86_cmp_imm32(cb, 10, access_size);
        size_t to_fail_size = x86_jnz_rel32(cb);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, excl_addr));
        x86_cmp_rr(cb, 10, 13);
        size_t to_fail_addr = x86_jnz_rel32(cb);

        /* Success path: in-bounds + store + status=0. */
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "STLXR");
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "STLXR");
        x86_mov_imm64(cb, 13, (uint64_t)(uintptr_t)guest_mem);
        x86_lea_r_from_base_index_disp32(cb, 10, 13, x86_rn, 0); /* r10 = host addr */
        x86_src = materialize_guest_xreg_or_zr_read(cb, rt, 13, pc, "STLXR");
        switch (size) {
            case 0:
                x86_mov_mem8_base_disp32_from_r(cb, 10, x86_src, 0);
                break;
            case 1:
                x86_mov_mem16_base_disp32_from_r(cb, 10, x86_src, 0);
                break;
            case 2:
                x86_mov_mem_base_disp32_from_r32(cb, 10, x86_src, 0);
                break;
            case 3:
                x86_mov_mem_base_disp32_from_r(cb, 10, 0, x86_src);
                break;
            default:
                fprintf(stderr, "invalid STLXR size at pc=%zu\n", pc);
                exit(1);
        }
        if (x86_rs >= 0) {
            x86_mov_imm64(cb, x86_rs, 0);
        } else {
            x86_mov_imm64(cb, 10, 0);
            writeback_guest_xreg_unless_zr(cb, rs, 10, pc, "STLXR");
        }
        size_t to_done = x86_jmp_rel32(cb);

        /* Fail path: status=1, no store. */
        size_t fail_off = cb->len;
        patch_rel32_at(cb->data, to_fail_valid, fail_off);
        patch_rel32_at(cb->data, to_fail_size, fail_off);
        patch_rel32_at(cb->data, to_fail_addr, fail_off);
        if (x86_rs >= 0) {
            x86_mov_imm64(cb, x86_rs, 1);
        } else {
            x86_mov_imm64(cb, 10, 1);
            writeback_guest_xreg_unless_zr(cb, rs, 10, pc, "STLXR");
        }

        size_t done_off = cb->len;
        patch_rel32_at(cb->data, to_done, done_off);

        /* STLXR always clears local exclusive monitor. */
        x86_mov_imm64(cb, 10, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_valid), 10);

        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* STXRB/STXRH/STXR Ws, Wt/Xt, [Xn|SP] */
    if ((insn & 0x3FE0FC00u) == 0x08007C00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rs = (insn >> 16) & 0x1Fu; /* status register (Ws) */
        unsigned rt = insn & 0x1Fu;         /* data register */
        unsigned rn = (insn >> 5) & 0x1Fu;  /* address base */
        int x86_rs = map_reg(rs);
        int x86_rn;
        int x86_src;
        uint32_t access_size = 1u << size;

        emit_preserve_guest_flags_begin(cb);

        /* r13 = effective host address (guest_mem + base). */
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "STXR");
        x86_mov_imm64(cb, 13, (uint64_t)(uintptr_t)guest_mem);
        x86_lea_r_from_base_index_disp32(cb, 13, 13, x86_rn, 0);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, excl_valid));
        x86_cmp_imm32(cb, 10, 1);
        size_t to_fail_valid = x86_jnz_rel32(cb);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, excl_size));
        x86_cmp_imm32(cb, 10, access_size);
        size_t to_fail_size = x86_jnz_rel32(cb);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, excl_addr));
        x86_cmp_rr(cb, 10, 13);
        size_t to_fail_addr = x86_jnz_rel32(cb);

        /* Success path: in-bounds + store + status=0. */
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "STXR");
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "STXR");
        x86_mov_imm64(cb, 13, (uint64_t)(uintptr_t)guest_mem);
        x86_lea_r_from_base_index_disp32(cb, 10, 13, x86_rn, 0); /* r10 = host addr */
        x86_src = materialize_guest_xreg_or_zr_read(cb, rt, 13, pc, "STXR");
        switch (size) {
            case 0:
                x86_mov_mem8_base_disp32_from_r(cb, 10, x86_src, 0);
                break;
            case 1:
                x86_mov_mem16_base_disp32_from_r(cb, 10, x86_src, 0);
                break;
            case 2:
                x86_mov_mem_base_disp32_from_r32(cb, 10, x86_src, 0);
                break;
            case 3:
                x86_mov_mem_base_disp32_from_r(cb, 10, 0, x86_src);
                break;
            default:
                fprintf(stderr, "invalid STXR size at pc=%zu\n", pc);
                exit(1);
        }
        if (x86_rs >= 0) {
            x86_mov_imm64(cb, x86_rs, 0);
        } else {
            x86_mov_imm64(cb, 10, 0);
            writeback_guest_xreg_unless_zr(cb, rs, 10, pc, "STXR");
        }
        size_t to_done = x86_jmp_rel32(cb);

        /* Fail path: status=1, no store. */
        size_t fail_off = cb->len;
        patch_rel32_at(cb->data, to_fail_valid, fail_off);
        patch_rel32_at(cb->data, to_fail_size, fail_off);
        patch_rel32_at(cb->data, to_fail_addr, fail_off);
        if (x86_rs >= 0) {
            x86_mov_imm64(cb, x86_rs, 1);
        } else {
            x86_mov_imm64(cb, 10, 1);
            writeback_guest_xreg_unless_zr(cb, rs, 10, pc, "STXR");
        }

        size_t done_off = cb->len;
        patch_rel32_at(cb->data, to_done, done_off);

        /* STXR always clears local exclusive monitor. */
        x86_mov_imm64(cb, 10, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, excl_valid), 10);

        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* STLRB/STLRH/STLR Wt/Xt, [Xn|SP] (release, no-offset) */
    if ((insn & 0x3FFFFC00u) == 0x089FFC00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_src;
        uint32_t access_size = 1u << size;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STLR");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);
        x86_src = (x86_rt >= 0) ? x86_rt : materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STLR");
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        switch (size) {
            case 0:
                x86_mov_mem8_base_index_disp32_from_r(cb, 10, x86_rn, x86_src, 0);
                break;
            case 1:
                x86_mov_mem16_base_index_disp32_from_r(cb, 10, x86_rn, x86_src, 0);
                break;
            case 2:
                x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_src, 0);
                break;
            case 3:
                x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_src, 0);
                break;
            default:
                fprintf(stderr, "invalid STLR size at pc=%zu\n", pc);
                exit(1);
        }
        return;
    }

    /* LDARB/LDARH/LDAR Wt/Xt, [Xn|SP] (acquire, no-offset) */
    if ((insn & 0x3FFFFC00u) == 0x08DFFC00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        uint32_t access_size = 1u << size;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDAR");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        switch (size) {
            case 0:
                x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 1:
                x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 2:
                x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            case 3:
                x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
                break;
            default:
                fprintf(stderr, "invalid LDAR size at pc=%zu\n", pc);
                exit(1);
        }
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDAR");
        }
        return;
    }

    /*
     * SWP / LDADD / LDCLR / LDEOR / LDSET family (byte/half/word/dword).
     * o3 (bit15): 1 => SWP*, 0 => LD* with opc in bits14:12.
     * opc (for o3=0):
     *   000=ADD, 001=BIC, 010=EOR, 011=ORR,
     *   100=SMAX, 101=SMIN, 110=UMAX, 111=UMIN.
     * A/R ordering bits are accepted and treated with same single-thread behavior.
     */
    if ((insn & 0x3F200C00u) == 0x38200000u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rs = (insn >> 16) & 0x1Fu;  /* source value register */
        unsigned o3 = (insn >> 15) & 1u;
        unsigned opc = (insn >> 12) & 0x7u;
        unsigned rn = (insn >> 5) & 0x1Fu;   /* address base */
        unsigned rt = insn & 0x1Fu;          /* result register */
        int x86_rn;
        uint32_t access_size = 1u << size;

        if (o3 != 0u && opc != 0u) {
            fprintf(stderr, "unsupported SWP*/LD* atomic variant at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SWP*/LD* atomics");
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);

        emit_preserve_guest_flags_begin(cb);
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SWP*/LD* atomics");
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_lea_r_from_base_index_disp32(cb, 10, 10, x86_rn, 0); /* r10 = guest base + base */
        switch (access_size) {
            case 1:
                x86_movzx_r32_from_mem8_base_disp32(cb, 13, 10, 0); /* r13 = old */
                break;
            case 2:
                x86_movzx_r32_from_mem16_base_disp32(cb, 13, 10, 0); /* r13 = old */
                break;
            case 4:
                x86_mov_r32_from_mem_base_disp32(cb, 13, 10, 0); /* r13 = old */
                break;
            case 8:
                x86_mov_r_from_mem_base_disp32(cb, 13, 10, 0); /* r13 = old */
                break;
            default:
                fprintf(stderr, "invalid access size in SWP*/LD* atomics at pc=%zu\n", pc);
                exit(1);
        }

        if (rs == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            int x86_src = materialize_guest_xreg_read(cb, rs, 10, pc, "SWP*/LD* atomics");
            if (x86_src != 10) {
                x86_mov_rr(cb, 10, x86_src); /* r10 = source value */
            }
        }
        emit_zero_extend_reg_for_size(cb, 10, access_size);

        if (o3 == 0u) {
            switch (opc) {
                case 0: /* LDADD* */
                    x86_add_rr(cb, 10, 13); /* r10 = src + old */
                    emit_zero_extend_reg_for_size(cb, 10, access_size);
                    break;
                case 1: /* LDCLR* (BIC) */
                    x86_not_r(cb, 10);      /* r10 = ~src */
                    x86_and_rr(cb, 10, 13); /* r10 = ~src & old */
                    break;
                case 2: /* LDEOR* */
                    x86_xor_rr(cb, 10, 13); /* r10 = src ^ old */
                    break;
                case 3: /* LDSET* */
                    x86_or_rr(cb, 10, 13);  /* r10 = src | old */
                    break;
                case 4: /* LDSMAX* (signed max) */
                    emit_sign_extend_reg_for_size(cb, 13, access_size);
                    emit_sign_extend_reg_for_size(cb, 10, access_size);
                    x86_cmp_rr(cb, 13, 10);
                    x86_cmovcc_rr(cb, 10, 13, 0xF); /* if old > src (signed), pick old */
                    break;
                case 5: /* LDSMIN* (signed min) */
                    emit_sign_extend_reg_for_size(cb, 13, access_size);
                    emit_sign_extend_reg_for_size(cb, 10, access_size);
                    x86_cmp_rr(cb, 13, 10);
                    x86_cmovcc_rr(cb, 10, 13, 0xC); /* if old < src (signed), pick old */
                    break;
                case 6: /* LDUMAX* (unsigned max) */
                    x86_cmp_rr(cb, 13, 10);
                    x86_cmovcc_rr(cb, 10, 13, 0x7); /* if old > src (unsigned), pick old */
                    break;
                case 7: /* LDUMIN* (unsigned min) */
                    x86_cmp_rr(cb, 13, 10);
                    x86_cmovcc_rr(cb, 10, 13, 0x2); /* if old < src (unsigned), pick old */
                    break;
                default:
                    fprintf(stderr, "internal unsupported LD* opc at pc=%zu\n", pc);
                    exit(1);
            }
        } /* else SWP*: r10 already holds replacement value */

        /* Preserve old/new while materializing guest base for the store. */
        x86_push_r(cb, 13); /* save old */
        x86_push_r(cb, 10); /* save new */
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SWP*/LD* atomics");
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_lea_r_from_base_index_disp32(cb, 10, 10, x86_rn, 0); /* r10 = guest base + base */
        x86_pop_r(cb, 13); /* r13 = new */

        switch (access_size) {
            case 1:
                x86_mov_mem8_base_disp32_from_r(cb, 10, 13, 0);
                break;
            case 2:
                x86_mov_mem16_base_disp32_from_r(cb, 10, 13, 0);
                break;
            case 4:
                x86_mov_mem_base_disp32_from_r32(cb, 10, 13, 0);
                break;
            case 8:
                x86_mov_mem_base_disp32_from_r(cb, 10, 0, 13);
                break;
            default:
                fprintf(stderr, "invalid store size in SWP*/LD* atomics at pc=%zu\n", pc);
                exit(1);
        }

        x86_pop_r(cb, 13); /* r13 = old */
        emit_zero_extend_reg_for_size(cb, 13, access_size);
        if (rt != 31u) {
            writeback_guest_xreg(cb, rt, 13, pc, "SWP*/LD* atomics");
        }

        emit_preserve_guest_flags_end(cb);
        return;
    }

    /*
     * CASP/CASPA/CASPL/CASPAL Ws/Xs, Ws2/Xs2, Wt/Xt, Wt2/Xt2, [Xn|SP]
     * L bit (bit 22) and o0 bit (bit 15) select ordering variants.
     * This PoC treats ordering variants with the same single-thread behavior.
     */
    if ((insn & 0xBFA07C00u) == 0x08207C00u) {
        unsigned sz = (insn >> 30) & 1u;   /* 0=32-bit, 1=64-bit */
        unsigned rs = (insn >> 16) & 0x1Fu; /* compare/result register pair base */
        unsigned rt = insn & 0x1Fu;         /* new-value register pair base */
        unsigned rn = (insn >> 5) & 0x1Fu;  /* address base */
        unsigned rs2 = rs + 1u;
        unsigned rt2 = rt + 1u;
        int x86_rs = map_reg(rs);
        int x86_rs2 = map_reg(rs2);
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;
        uint32_t access_size = sz ? 8u : 4u; /* per element */

        if (rs >= 30u || rt >= 30u || (rs & 1u) != 0 || (rt & 1u) != 0) {
            fprintf(stderr, "CASP* requires even register pairs at pc=%zu\n", pc);
            exit(1);
        }

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "CASP*");
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size * 2u, pc);

        emit_preserve_guest_flags_begin(cb);
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "CASP*");
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_lea_r_from_base_index_disp32(cb, 10, 10, x86_rn, 0); /* r10 = guest base + base */
        if (sz) {
            x86_mov_r_from_mem_base_disp32(cb, 13, 10, 0); /* old low */
            x86_mov_r_from_mem_base_disp32(cb, 10, 10, (int32_t)access_size); /* old high */
        } else {
            x86_mov_r32_from_mem_base_disp32(cb, 13, 10, 0); /* old low */
            x86_mov_r32_from_mem_base_disp32(cb, 10, 10, (int32_t)access_size); /* old high */
        }

        if (x86_rs >= 0) {
            x86_cmp_rr(cb, 13, x86_rs);
        } else {
            x86_push_r(cb, 10); /* preserve old high */
            x86_rs = materialize_guest_xreg_read(cb, rs, 10, pc, "CASP*");
            x86_cmp_rr(cb, 13, x86_rs);
            x86_pop_r(cb, 10); /* restore old high */
        }
        size_t to_fail_low = x86_jnz_rel32(cb);
        if (x86_rs2 >= 0) {
            x86_cmp_rr(cb, 10, x86_rs2);
        } else {
            x86_push_r(cb, 13); /* preserve old low */
            x86_rs2 = materialize_guest_xreg_read(cb, rs2, 13, pc, "CASP*");
            x86_cmp_rr(cb, 10, x86_rs2);
            x86_pop_r(cb, 13); /* restore old low */
        }
        size_t to_fail_high = x86_jnz_rel32(cb);

        /* Success path: store new pair while preserving old values for writeback. */
        x86_push_r(cb, 10);
        x86_push_r(cb, 13);
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "CASP*");
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_lea_r_from_base_index_disp32(cb, 10, 10, x86_rn, 0); /* r10 = guest base + base */
        x86_rt = materialize_guest_xreg_read(cb, rt, 13, pc, "CASP*");
        if (sz) {
            x86_mov_mem_base_disp32_from_r(cb, 10, 0, x86_rt);
        } else {
            x86_mov_mem_base_disp32_from_r32(cb, 10, x86_rt, 0);
        }
        x86_rt2 = materialize_guest_xreg_read(cb, rt2, 13, pc, "CASP*");
        if (sz) {
            x86_mov_mem_base_disp32_from_r(cb, 10, (int32_t)access_size, x86_rt2);
        } else {
            x86_mov_mem_base_disp32_from_r32(cb, 10, x86_rt2, (int32_t)access_size);
        }
        x86_pop_r(cb, 13); /* restore old low */
        x86_pop_r(cb, 10); /* restore old high */
        size_t to_join = x86_jmp_rel32(cb);

        size_t fail_off = cb->len;
        patch_rel32_at(cb->data, to_fail_low, fail_off);
        patch_rel32_at(cb->data, to_fail_high, fail_off);

        size_t join_off = cb->len;
        patch_rel32_at(cb->data, to_join, join_off);

        /* CASP* writes back the previous memory pair to Rs/Rs2 on success/fail. */
        writeback_guest_xreg(cb, rs, 13, pc, "CASP*");
        writeback_guest_xreg(cb, rs2, 10, pc, "CASP*");

        emit_preserve_guest_flags_end(cb);
        return;
    }

    /*
     * CASB/CASH/CAS/CASA/CASL/CASAL (+ byte/halfword A/L variants), [Xn|SP]
     * L bit (bit 22) and o0 bit (bit 15) select ordering variants.
     * This PoC treats ordering variants with the same single-thread behavior.
     */
    if ((insn & 0x3FA07C00u) == 0x08A07C00u) {
        unsigned size = (insn >> 30) & 0x3u; /* 0=8, 1=16, 2=32, 3=64 */
        unsigned rs = (insn >> 16) & 0x1Fu; /* compare/result register */
        unsigned rt = insn & 0x1Fu;         /* new-value register */
        unsigned rn = (insn >> 5) & 0x1Fu;  /* address base */
        int x86_rs = (rs == 31u) ? -1 : map_reg(rs);
        int x86_rn;
        uint32_t access_size = 1u << size;
        int x86_cmp_src;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "CAS*");
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, access_size, pc);

        emit_preserve_guest_flags_begin(cb);

        /*
         * cmpxchg always compares against RAX/EAX.
         * Rt==WZR/XZR uses a synthetic zero source in r13.
         * Load compare into RAX first, then materialize replacement value.
         */
        if (rs == 31u) {
            x86_mov_imm64(cb, 0, 0);
        } else {
            x86_rs = materialize_guest_xreg_read(cb, rs, 13, pc, "CAS*");
            if (x86_rs != 0) {
                x86_mov_rr(cb, 0, x86_rs);
            }
        }

        if (rt == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_cmp_src = 13;
        } else {
            x86_cmp_src = materialize_guest_xreg_read(cb, rt, 13, pc, "CAS*");
            if (x86_cmp_src == 0) {
                x86_mov_rr(cb, 13, 0);
                x86_cmp_src = 13;
            }
        }

        /*
         * Materialize host address in r10. If replacement currently lives in r13 and rn is
         * unmapped, preserve replacement while reusing r13 scratch for rn materialization.
         */
        if ((rn == 31u || map_reg(rn) < 0) && x86_cmp_src == 13) {
            x86_push_r(cb, 13);
            x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "CAS*");
            x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
            x86_lea_r_from_base_index_disp32(cb, 10, 10, x86_rn, 0);
            x86_pop_r(cb, 13);
        } else {
            x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "CAS*");
            x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
            x86_lea_r_from_base_index_disp32(cb, 10, 10, x86_rn, 0);
        }

        x86_lock_cmpxchg_mem_base_disp32_from_r(cb, 10, x86_cmp_src, 0, access_size);

        if (access_size == 1u || access_size == 2u) {
            x86_mov_imm64(cb, 13, access_size == 1u ? 0xFFu : 0xFFFFu);
            x86_and_rr(cb, 0, 13); /* zero-extend AL/AX to architectural W result */
        }

        if (rs != 31u) {
            writeback_guest_xreg(cb, rs, 0, pc, "CAS*");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* MOVZ Xd, #imm16, LSL #(hw*16) */
    if ((insn & 0xFF800000u) == 0xD2800000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned hw = (insn >> 21) & 0x3u;
        uint64_t imm16 = (insn >> 5) & 0xFFFFu;
        uint64_t imm = imm16 << (hw * 16u);
        if (rd == 31u) {
            return; /* write-discard to XZR */
        }
        x86_mov_imm64(cb, 10, imm);
        writeback_guest_xreg(cb, rd, 10, pc, "MOVZ");
        return;
    }

    /* MOVN Xd, #imm16, LSL #(hw*16) */
    if ((insn & 0xFF800000u) == 0x92800000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned hw = (insn >> 21) & 0x3u;
        uint64_t imm16 = (insn >> 5) & 0xFFFFu;
        uint64_t imm = imm16 << (hw * 16u);
        uint64_t value = ~imm;
        if (rd == 31u) {
            return; /* write-discard to XZR */
        }
        x86_mov_imm64(cb, 10, value);
        writeback_guest_xreg(cb, rd, 10, pc, "MOVN");
        return;
    }

    /* MOVK Xd, #imm16, LSL #(hw*16) */
    if ((insn & 0xFF800000u) == 0xF2800000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned hw = (insn >> 21) & 0x3u;
        uint64_t imm16 = (insn >> 5) & 0xFFFFu;
        uint64_t shift = hw * 16u;
        uint64_t keep_mask = ~(0xFFFFULL << shift);
        uint64_t insert_bits = imm16 << shift;
        int x86_rd;
        const int tmp = 10; /* scratch */

        if (rd == 31u) {
            return; /* write-discard to XZR */
        }
        x86_rd = materialize_guest_xreg_read(cb, rd, 13, pc, "MOVK");

        emit_preserve_guest_flags_begin(cb);
        x86_mov_imm64(cb, tmp, keep_mask);
        x86_and_rr(cb, x86_rd, tmp);
        x86_mov_imm64(cb, tmp, insert_bits);
        x86_or_rr(cb, x86_rd, tmp);
        writeback_guest_xreg(cb, rd, x86_rd, pc, "MOVK");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* MOVZ Wd, #imm16, LSL #(hw*16) */
    if ((insn & 0xFF800000u) == 0x52800000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned hw = (insn >> 21) & 0x3u;
        uint32_t imm16 = (insn >> 5) & 0xFFFFu;
        uint32_t imm;
        int x86_rd;
        int x86_dst;

        if (hw > 1u) {
            fprintf(stderr, "MOVZ (W) with hw>1 unsupported at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write-discard to WZR */
        }

        imm = imm16 << (hw * 16u);
        x86_rd = map_reg(rd);
        x86_dst = (x86_rd >= 0) ? x86_rd : 10;
        x86_mov_imm64(cb, x86_dst, (uint64_t)imm);
        writeback_guest_xreg(cb, rd, x86_dst, pc, "MOVZ (W)");
        return;
    }

    /* MOVN Wd, #imm16, LSL #(hw*16) */
    if ((insn & 0xFF800000u) == 0x12800000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned hw = (insn >> 21) & 0x3u;
        uint32_t imm16 = (insn >> 5) & 0xFFFFu;
        uint32_t imm;
        uint32_t value;
        int x86_rd;
        int x86_dst;

        if (hw > 1u) {
            fprintf(stderr, "MOVN (W) with hw>1 unsupported at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write-discard to WZR */
        }

        imm = imm16 << (hw * 16u);
        value = ~imm;
        x86_rd = map_reg(rd);
        x86_dst = (x86_rd >= 0) ? x86_rd : 10;
        x86_mov_imm64(cb, x86_dst, (uint64_t)value);
        writeback_guest_xreg(cb, rd, x86_dst, pc, "MOVN (W)");
        return;
    }

    /* MOVK Wd, #imm16, LSL #(hw*16) */
    if ((insn & 0xFF800000u) == 0x72800000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned hw = (insn >> 21) & 0x3u;
        uint64_t imm16 = (insn >> 5) & 0xFFFFu;
        uint64_t shift = hw * 16u;
        uint64_t keep_mask;
        uint64_t insert_bits;
        int x86_rd;
        const int tmp = 10; /* scratch */

        if (hw > 1u) {
            fprintf(stderr, "MOVK (W) with hw>1 unsupported at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write-discard to WZR */
        }

        keep_mask = (~(0xFFFFULL << shift)) & 0xFFFFFFFFULL;
        insert_bits = (imm16 << shift) & 0xFFFFFFFFULL;
        x86_rd = materialize_guest_xreg_read(cb, rd, 13, pc, "MOVK (W)");

        emit_preserve_guest_flags_begin(cb);
        x86_mov_imm64(cb, tmp, keep_mask);
        x86_and_rr(cb, x86_rd, tmp);
        x86_mov_imm64(cb, tmp, insert_bits);
        x86_or_rr(cb, x86_rd, tmp);
        writeback_guest_xreg(cb, rd, x86_rd, pc, "MOVK (W)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* AND/ORR/EOR/ANDS {W,X}d, {W,X}n, #imm (logical immediate class). */
    if ((insn & 0x1F800000u) == 0x12000000u) {
        unsigned sf = (insn >> 31) & 0x1u;
        unsigned opc = (insn >> 29) & 0x3u;
        unsigned n = (insn >> 22) & 0x1u;
        unsigned immr = (insn >> 16) & 0x3Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rd = insn & 0x1Fu;
        uint64_t imm_mask;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;
        const bool is_w = (sf == 0u);
        const bool set_flags = (opc == 3u);

        if (!decode_logical_immediate_mask(sf, n, immr, imms, &imm_mask)) {
            fprintf(stderr, "invalid logical-immediate encoding at pc=%zu\n", pc);
            exit(1);
        }
        if (is_w) {
            imm_mask &= 0xFFFFFFFFull;
        }

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc,
                                                 is_w ? "logical imm (W)" : "logical imm (X)");
        }

        if (!set_flags && rd == 31u) {
            return; /* write to WZR/XZR: architectural no-op */
        }

        if (set_flags) {
            if (rd == 31u) { /* TST alias */
                x86_mov_imm64(cb, 10, imm_mask);
                if (is_w) {
                    x86_test_rr32(cb, x86_rn, 10);
                } else {
                    x86_test_rr(cb, x86_rn, 10);
                }
                return;
            }

            x86_dst = (x86_rd >= 0) ? x86_rd : 13;
            if (is_w) {
                if (x86_dst != x86_rn) {
                    x86_mov_rr32(cb, x86_dst, x86_rn);
                }
                x86_mov_imm64(cb, 10, imm_mask);
                x86_and_rr32(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "ANDS (W, imm)");
            } else {
                if (x86_dst != x86_rn) {
                    x86_mov_rr(cb, x86_dst, x86_rn);
                }
                x86_mov_imm64(cb, 10, imm_mask);
                x86_and_rr(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "ANDS (X, imm)");
            }
            return;
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;
        emit_preserve_guest_flags_begin(cb);
        if (is_w) {
            if (x86_dst != x86_rn) {
                x86_mov_rr32(cb, x86_dst, x86_rn);
            }
            x86_mov_imm64(cb, 10, imm_mask);
            if (opc == 0u) {
                x86_and_rr32(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "AND (W, imm)");
            } else if (opc == 1u) {
                x86_or_rr32(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "ORR (W, imm)");
            } else if (opc == 2u) {
                x86_xor_rr32(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "EOR (W, imm)");
            }
        } else {
            if (x86_dst != x86_rn) {
                x86_mov_rr(cb, x86_dst, x86_rn);
            }
            x86_mov_imm64(cb, 10, imm_mask);
            if (opc == 0u) {
                x86_and_rr(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "AND (X, imm)");
            } else if (opc == 1u) {
                x86_or_rr(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "ORR (X, imm)");
            } else if (opc == 2u) {
                x86_xor_rr(cb, x86_dst, 10);
                writeback_guest_xreg(cb, rd, x86_dst, pc, "EOR (X, imm)");
            }
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* UBFM Wd, Wn, #immr, #imms (also aliases like LSL/LSR/UBFX/UBFIZ). */
    if ((insn & 0xFFC00000u) == 0x53000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned immr = (insn >> 16) & 0x3Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;
        unsigned width;
        uint64_t mask;

        if (immr > 31u || imms > 31u) {
            fprintf(stderr, "invalid UBFM (W) immediates at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write to WZR: architectural no-op */
        }

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc, "UBFM (W)");
        }
        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }

        if (immr <= imms) {
            if (immr != 0u) {
                x86_shift_imm32(cb, x86_dst, 1, immr); /* LSR */
            }
            width = imms - immr + 1u;
        } else {
            unsigned lshift = 32u - immr;
            x86_shift_imm32(cb, x86_dst, 0, lshift); /* LSL */
            width = imms + 1u;
        }

        if (width < 32u) {
            mask = (1ull << width) - 1ull;
            x86_mov_imm64(cb, 10, mask);
            x86_and_rr32(cb, x86_dst, 10);
        }
        writeback_guest_xreg(cb, rd, x86_dst, pc, "UBFM (W)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* UBFM Xd, Xn, #immr, #imms (also aliases like LSL/LSR/UBFX/UBFIZ). */
    if ((insn & 0xFFC00000u) == 0xD3400000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned immr = (insn >> 16) & 0x3Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;
        unsigned width;
        uint64_t mask;

        if (rd == 31u) {
            return; /* write to XZR: architectural no-op */
        }

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc, "UBFM (X)");
        }
        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }

        if (immr <= imms) {
            if (immr != 0u) {
                x86_shift_imm(cb, x86_dst, 1, immr); /* LSR */
            }
            width = imms - immr + 1u;
        } else {
            unsigned lshift = 64u - immr;
            x86_shift_imm(cb, x86_dst, 0, lshift); /* LSL */
            width = imms + 1u;
        }

        if (width < 64u) {
            mask = (1ull << width) - 1ull;
            x86_mov_imm64(cb, 10, mask);
            x86_and_rr(cb, x86_dst, 10);
        }
        writeback_guest_xreg(cb, rd, x86_dst, pc, "UBFM (X)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SBFM Wd, Wn, #immr, #imms (aliases like ASR/SBFX/SBFIZ). */
    if ((insn & 0xFFC00000u) == 0x13000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned immr = (insn >> 16) & 0x3Fu;
        unsigned width;
        unsigned shift;
        uint64_t mask;

        if (immr > 31u || imms > 31u) {
            fprintf(stderr, "invalid SBFM (W) immediates at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write to WZR */
        }

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            int src = materialize_guest_xreg_read(cb, rn, 13, pc, "SBFM (W)");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }

        if (immr <= imms) {
            if (immr != 0u) {
                x86_shift_imm32(cb, 10, 1, immr); /* LSR */
            }
            width = imms - immr + 1u;
        } else {
            x86_shift_imm32(cb, 10, 0, 32u - immr); /* LSL */
            width = imms + 1u;
        }

        if (width < 32u) {
            mask = bitmask_width_u64(width);
            x86_mov_imm64(cb, 13, mask);
            x86_and_rr32(cb, 10, 13);
            shift = 32u - width;
            x86_shift_imm32(cb, 10, 0, shift); /* SHL */
            x86_shift_imm32(cb, 10, 2, shift); /* SAR */
        }
        writeback_guest_xreg(cb, rd, 10, pc, "SBFM (W)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SBFM Xd, Xn, #immr, #imms (aliases like ASR/SBFX/SBFIZ). */
    if ((insn & 0xFFC00000u) == 0x93400000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned immr = (insn >> 16) & 0x3Fu;
        unsigned width;
        unsigned shift;
        uint64_t mask;

        if (rd == 31u) {
            return; /* write to XZR */
        }

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            int src = materialize_guest_xreg_read(cb, rn, 13, pc, "SBFM (X)");
            if (src != 10) {
                x86_mov_rr(cb, 10, src);
            }
        }

        if (immr <= imms) {
            if (immr != 0u) {
                x86_shift_imm(cb, 10, 1, immr); /* LSR */
            }
            width = imms - immr + 1u;
        } else {
            x86_shift_imm(cb, 10, 0, 64u - immr); /* LSL */
            width = imms + 1u;
        }

        if (width < 64u) {
            mask = bitmask_width_u64(width);
            x86_mov_imm64(cb, 13, mask);
            x86_and_rr(cb, 10, 13);
            shift = 64u - width;
            x86_shift_imm(cb, 10, 0, shift); /* SHL */
            x86_shift_imm(cb, 10, 2, shift); /* SAR */
        }
        writeback_guest_xreg(cb, rd, 10, pc, "SBFM (X)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* BFM Wd, Wn, #immr, #imms (aliases like BFXIL/BFI). */
    if ((insn & 0xFFC00000u) == 0x33000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned immr = (insn >> 16) & 0x3Fu;
        unsigned width;
        unsigned lshift;
        uint64_t lowmask;
        uint64_t mask;

        if (immr > 31u || imms > 31u) {
            fprintf(stderr, "invalid BFM (W) immediates at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write to WZR */
        }

        emit_preserve_guest_flags_begin(cb);

        /* Build field in r10. */
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            int src = materialize_guest_xreg_read(cb, rn, 13, pc, "BFM (W)");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }

        if (immr <= imms) {
            width = imms - immr + 1u;
            if (immr != 0u) {
                x86_shift_imm32(cb, 10, 1, immr); /* LSR */
            }
            lowmask = bitmask_width_u64(width);
            mask = lowmask;
            if (width < 32u) {
                x86_mov_imm64(cb, 13, lowmask);
                x86_and_rr32(cb, 10, 13);
            }
        } else {
            width = imms + 1u;
            lshift = 32u - immr;
            lowmask = bitmask_width_u64(width);
            x86_mov_imm64(cb, 13, lowmask);
            x86_and_rr32(cb, 10, 13);
            if (lshift != 0u) {
                x86_shift_imm32(cb, 10, 0, lshift); /* LSL */
            }
            mask = lowmask << lshift;
        }

        x86_push_r(cb, 10); /* save field */
        {
            int dst_old = materialize_guest_xreg_read(cb, rd, 13, pc, "BFM (W)");
            if (dst_old != 13) {
                x86_mov_rr32(cb, 13, dst_old);
            }
        }
        x86_mov_imm64(cb, 10, mask);
        x86_not_r32(cb, 10);
        x86_and_rr32(cb, 13, 10); /* clear destination field bits */
        x86_pop_r(cb, 10);         /* restore field */
        x86_or_rr32(cb, 13, 10);
        writeback_guest_xreg(cb, rd, 13, pc, "BFM (W)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* BFM Xd, Xn, #immr, #imms (aliases like BFXIL/BFI). */
    if ((insn & 0xFFC00000u) == 0xB3400000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imms = (insn >> 10) & 0x3Fu;
        unsigned immr = (insn >> 16) & 0x3Fu;
        unsigned width;
        unsigned lshift;
        uint64_t lowmask;
        uint64_t mask;

        if (rd == 31u) {
            return; /* write to XZR */
        }

        emit_preserve_guest_flags_begin(cb);

        /* Build field in r10. */
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            int src = materialize_guest_xreg_read(cb, rn, 13, pc, "BFM (X)");
            if (src != 10) {
                x86_mov_rr(cb, 10, src);
            }
        }

        if (immr <= imms) {
            width = imms - immr + 1u;
            if (immr != 0u) {
                x86_shift_imm(cb, 10, 1, immr); /* LSR */
            }
            lowmask = bitmask_width_u64(width);
            mask = lowmask;
            if (width < 64u) {
                x86_mov_imm64(cb, 13, lowmask);
                x86_and_rr(cb, 10, 13);
            }
        } else {
            width = imms + 1u;
            lshift = 64u - immr;
            lowmask = bitmask_width_u64(width);
            x86_mov_imm64(cb, 13, lowmask);
            x86_and_rr(cb, 10, 13);
            if (lshift != 0u) {
                x86_shift_imm(cb, 10, 0, lshift); /* LSL */
            }
            mask = lowmask << lshift;
        }

        x86_push_r(cb, 10); /* save field */
        {
            int dst_old = materialize_guest_xreg_read(cb, rd, 13, pc, "BFM (X)");
            if (dst_old != 13) {
                x86_mov_rr(cb, 13, dst_old);
            }
        }
        x86_mov_imm64(cb, 10, mask);
        x86_not_r(cb, 10);
        x86_and_rr(cb, 13, 10); /* clear destination field bits */
        x86_pop_r(cb, 10);       /* restore field */
        x86_or_rr(cb, 13, 10);
        writeback_guest_xreg(cb, rd, 13, pc, "BFM (X)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* LSLV/LSRV/ASRV/RORV Xd, Xn, Xm (data-processing 2-source variable shifts). */
    if ((insn & 0xFFE0FC00u) == 0x9AC02000u || (insn & 0xFFE0FC00u) == 0x9AC02400u ||
        (insn & 0xFFE0FC00u) == 0x9AC02800u || (insn & 0xFFE0FC00u) == 0x9AC02C00u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned op = insn & 0x0000FC00u;
        unsigned shift_kind;
        int src;
        int x86_rm;
        bool restore_rcx;

        switch (op) {
            case 0x00002000u:
                shift_kind = 0; /* LSLV */
                break;
            case 0x00002400u:
                shift_kind = 1; /* LSRV */
                break;
            case 0x00002800u:
                shift_kind = 2; /* ASRV */
                break;
            default:
                shift_kind = 3; /* RORV */
                break;
        }

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "var-shift (X)");
            if (src != 10) {
                x86_mov_rr(cb, 10, src);
            }
        }

        restore_rcx = (rd != 1u);
        if (restore_rcx) {
            x86_push_r(cb, 1);
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 1, 0);
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 13, pc, "var-shift (X)");
            if (x86_rm != 1) {
                x86_mov_rr(cb, 1, x86_rm);
            }
        }
        x86_shift_cl(cb, 10, shift_kind);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, 10, pc, "var-shift (X)");
        }
        if (restore_rcx) {
            x86_pop_r(cb, 1);
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* LSLV/LSRV/ASRV/RORV Wd, Wn, Wm (data-processing 2-source variable shifts). */
    if ((insn & 0xFFE0FC00u) == 0x1AC02000u || (insn & 0xFFE0FC00u) == 0x1AC02400u ||
        (insn & 0xFFE0FC00u) == 0x1AC02800u || (insn & 0xFFE0FC00u) == 0x1AC02C00u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned op = insn & 0x0000FC00u;
        unsigned shift_kind;
        int src;
        int x86_rm;
        bool restore_rcx;

        switch (op) {
            case 0x00002000u:
                shift_kind = 0; /* LSLV */
                break;
            case 0x00002400u:
                shift_kind = 1; /* LSRV */
                break;
            case 0x00002800u:
                shift_kind = 2; /* ASRV */
                break;
            default:
                shift_kind = 3; /* RORV */
                break;
        }

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "var-shift (W)");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }

        restore_rcx = (rd != 1u);
        if (restore_rcx) {
            x86_push_r(cb, 1);
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 1, 0);
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 13, pc, "var-shift (W)");
            if (x86_rm != 1) {
                x86_mov_rr32(cb, 1, x86_rm);
            }
        }
        x86_shift_cl32(cb, 10, shift_kind);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, 10, pc, "var-shift (W)");
        }
        if (restore_rcx) {
            x86_pop_r(cb, 1);
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* EXTR {Wd, Wn, Wm}/{Xd, Xn, Xm}, #lsb (ROR alias when Rn == Rm). */
    if ((insn & 0x7F800000u) == 0x13800000u) {
        unsigned sf = (insn >> 31) & 1u;
        unsigned n = (insn >> 22) & 1u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned lsb = (insn >> 10) & 0x3Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rd = insn & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        if (n != sf) {
            fprintf(stderr, "unsupported EXTR encoding (N != sf) at pc=%zu\n", pc);
            exit(1);
        }
        if (!sf && (lsb & 0x20u)) {
            fprintf(stderr, "unsupported EXTR (W) lsb>=32 at pc=%zu\n", pc);
            exit(1);
        }

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, sf ? "EXTR (X)" : "EXTR (W)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, sf ? "EXTR (X)" : "EXTR (W)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (sf) {
            if (x86_dst != x86_rn) {
                x86_mov_rr(cb, x86_dst, x86_rn);
            }
            if (lsb != 0u) {
                x86_shift_imm(cb, x86_dst, 1, lsb); /* LSR */
                if (x86_rm != tmp) {
                    x86_mov_rr(cb, tmp, x86_rm);
                }
                x86_shift_imm(cb, tmp, 0, 64u - lsb); /* LSL */
                x86_or_rr(cb, x86_dst, tmp);
            }
        } else {
            if (x86_dst != x86_rn) {
                x86_mov_rr32(cb, x86_dst, x86_rn);
            }
            if (lsb != 0u) {
                x86_shift_imm32(cb, x86_dst, 1, lsb); /* LSR */
                if (x86_rm != tmp) {
                    x86_mov_rr32(cb, tmp, x86_rm);
                }
                x86_shift_imm32(cb, tmp, 0, 32u - lsb); /* LSL */
                x86_or_rr32(cb, x86_dst, tmp);
            }
        }
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, sf ? "EXTR (X)" : "EXTR (W)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* UDIV Xd, Xn, Xm */
    if ((insn & 0xFFE0FC00u) == 0x9AC00800u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        size_t to_zero;
        size_t to_join;

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc, "UDIV");
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "UDIV");
            if (x86_rm != 10) {
                x86_mov_rr(cb, 10, x86_rm);
            }
            x86_rm = 10;
        }
        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        x86_cmp_imm32(cb, x86_rm, 0);
        to_zero = x86_jz_rel32(cb);

        if (rn == 31u) {
            x86_mov_imm64(cb, 0, 0);
        } else if (x86_rn != 0) {
            x86_mov_rr(cb, 0, x86_rn);
        }
        x86_xor_rr(cb, 2, 2); /* rdx = 0 */
        x86_div_r(cb, x86_rm);
        if (rd != 31u) {
            if (x86_dst != 0) {
                x86_mov_rr(cb, x86_dst, 0);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "UDIV");
        }
        to_join = x86_jmp_rel32(cb);

        patch_rel32_at(cb->data, to_zero, cb->len);
        if (rd != 31u) {
            x86_mov_imm64(cb, x86_dst, 0);
            writeback_guest_xreg(cb, rd, x86_dst, pc, "UDIV");
        }
        patch_rel32_at(cb->data, to_join, cb->len);
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SDIV Xd, Xn, Xm */
    if ((insn & 0xFFE0FC00u) == 0x9AC00C00u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        size_t to_zero;
        size_t to_join;
        size_t to_do_div_a;
        size_t to_do_div_b;
        size_t to_after_div;

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc, "SDIV");
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "SDIV");
            if (x86_rm != 10) {
                x86_mov_rr(cb, 10, x86_rm);
            }
            x86_rm = 10;
        }
        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        x86_cmp_imm32(cb, x86_rm, 0);
        to_zero = x86_jz_rel32(cb);

        if (rn == 31u) {
            x86_mov_imm64(cb, 0, 0);
        } else if (x86_rn != 0) {
            x86_mov_rr(cb, 0, x86_rn);
        }
        /* Avoid x86 idiv overflow trap for INT64_MIN / -1; AArch64 returns INT64_MIN. */
        x86_cmp_imm32(cb, x86_rm, 0xFFFFFFFFu);
        to_do_div_a = x86_jnz_rel32(cb);
        x86_mov_imm64(cb, 12, 0x8000000000000000ull);
        x86_cmp_rr(cb, 0, 12);
        to_do_div_b = x86_jnz_rel32(cb);
        to_after_div = x86_jmp_rel32(cb);

        patch_rel32_at(cb->data, to_do_div_a, cb->len);
        patch_rel32_at(cb->data, to_do_div_b, cb->len);
        x86_cqo(cb);
        x86_idiv_r(cb, x86_rm);
        patch_rel32_at(cb->data, to_after_div, cb->len);
        if (rd != 31u) {
            if (x86_dst != 0) {
                x86_mov_rr(cb, x86_dst, 0);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SDIV");
        }
        to_join = x86_jmp_rel32(cb);

        patch_rel32_at(cb->data, to_zero, cb->len);
        if (rd != 31u) {
            x86_mov_imm64(cb, x86_dst, 0);
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SDIV");
        }
        patch_rel32_at(cb->data, to_join, cb->len);
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* UDIV Wd, Wn, Wm */
    if ((insn & 0xFFE0FC00u) == 0x1AC00800u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        size_t to_zero;
        size_t to_join;

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc, "UDIV (W)");
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "UDIV (W)");
            if (x86_rm != 10) {
                x86_mov_rr32(cb, 10, x86_rm);
            }
            x86_rm = 10;
        }
        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        x86_cmp_imm32_32(cb, x86_rm, 0);
        to_zero = x86_jz_rel32(cb);

        if (rn == 31u) {
            x86_mov_imm64(cb, 0, 0);
        } else if (x86_rn != 0) {
            x86_mov_rr32(cb, 0, x86_rn);
        } else {
            x86_mov_rr32(cb, 0, 0);
        }
        x86_xor_rr32(cb, 2, 2); /* edx = 0 */
        x86_div_r32(cb, x86_rm);
        if (rd != 31u) {
            if (x86_dst != 0) {
                x86_mov_rr32(cb, x86_dst, 0);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "UDIV (W)");
        }
        to_join = x86_jmp_rel32(cb);

        patch_rel32_at(cb->data, to_zero, cb->len);
        if (rd != 31u) {
            x86_mov_imm64(cb, x86_dst, 0);
            writeback_guest_xreg(cb, rd, x86_dst, pc, "UDIV (W)");
        }
        patch_rel32_at(cb->data, to_join, cb->len);
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SDIV Wd, Wn, Wm */
    if ((insn & 0xFFE0FC00u) == 0x1AC00C00u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        size_t to_zero;
        size_t to_join;
        size_t to_do_div_a;
        size_t to_do_div_b;
        size_t to_after_div;

        if (rn == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_rn = 13;
        } else {
            x86_rn = materialize_guest_xreg_read(cb, rn, 13, pc, "SDIV (W)");
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "SDIV (W)");
            if (x86_rm != 10) {
                x86_mov_rr32(cb, 10, x86_rm);
            }
            x86_rm = 10;
        }
        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        x86_cmp_imm32_32(cb, x86_rm, 0);
        to_zero = x86_jz_rel32(cb);

        if (rn == 31u) {
            x86_mov_imm64(cb, 0, 0);
        } else if (x86_rn != 0) {
            x86_mov_rr32(cb, 0, x86_rn);
        } else {
            x86_mov_rr32(cb, 0, 0);
        }
        /* Avoid x86 idiv overflow trap for INT32_MIN / -1; AArch64 returns INT32_MIN. */
        x86_cmp_imm32_32(cb, x86_rm, 0xFFFFFFFFu);
        to_do_div_a = x86_jnz_rel32(cb);
        x86_cmp_imm32_32(cb, 0, 0x80000000u);
        to_do_div_b = x86_jnz_rel32(cb);
        to_after_div = x86_jmp_rel32(cb);

        patch_rel32_at(cb->data, to_do_div_a, cb->len);
        patch_rel32_at(cb->data, to_do_div_b, cb->len);
        x86_cdq(cb);
        x86_idiv_r32(cb, x86_rm);
        patch_rel32_at(cb->data, to_after_div, cb->len);
        if (rd != 31u) {
            if (x86_dst != 0) {
                x86_mov_rr32(cb, x86_dst, 0);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SDIV (W)");
        }
        to_join = x86_jmp_rel32(cb);

        patch_rel32_at(cb->data, to_zero, cb->len);
        if (rd != 31u) {
            x86_mov_imm64(cb, x86_dst, 0);
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SDIV (W)");
        }
        patch_rel32_at(cb->data, to_join, cb->len);
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* UMADDL Xd, Wn, Wm, Xa (UMULL alias when Xa==XZR). */
    if ((insn & 0xFFE08000u) == 0x9BA00000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "UMADDL");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "UMADDL");
            if (src != 13) {
                x86_mov_rr32(cb, 13, src);
            }
        }
        x86_imul_rr(cb, 10, 13); /* low 64-bit product of zero-extended 32-bit operands */
        if (ra != 31u) {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "UMADDL");
            x86_add_rr(cb, 10, x86_ra);
        }
        if (rd != 31u) {
            if (x86_dst != 10) {
                x86_mov_rr(cb, x86_dst, 10);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "UMADDL");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* UMSUBL Xd, Wn, Wm, Xa */
    if ((insn & 0xFFE08000u) == 0x9BA08000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "UMSUBL");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "UMSUBL");
            if (src != 13) {
                x86_mov_rr32(cb, 13, src);
            }
        }
        x86_imul_rr(cb, 10, 13); /* low 64-bit product of zero-extended 32-bit operands */
        if (ra == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_ra = 13;
        } else {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "UMSUBL");
            if (x86_ra != 13) {
                x86_mov_rr(cb, 13, x86_ra);
            }
            x86_ra = 13;
        }
        x86_sub_rr(cb, x86_ra, 10);
        if (rd != 31u) {
            if (x86_dst != x86_ra) {
                x86_mov_rr(cb, x86_dst, x86_ra);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "UMSUBL");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SMADDL Xd, Wn, Wm, Xa (SMULL alias when Xa==XZR). */
    if ((insn & 0xFFE08000u) == 0x9B200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "SMADDL");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
            x86_movsxd_rr(cb, 10, 10);
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "SMADDL");
            if (src != 13) {
                x86_mov_rr32(cb, 13, src);
            }
            x86_movsxd_rr(cb, 13, 13);
        }
        x86_imul_rr(cb, 10, 13);
        if (ra != 31u) {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "SMADDL");
            x86_add_rr(cb, 10, x86_ra);
        }
        if (rd != 31u) {
            if (x86_dst != 10) {
                x86_mov_rr(cb, x86_dst, 10);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SMADDL");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SMSUBL Xd, Wn, Wm, Xa */
    if ((insn & 0xFFE08000u) == 0x9B208000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "SMSUBL");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
            x86_movsxd_rr(cb, 10, 10);
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "SMSUBL");
            if (src != 13) {
                x86_mov_rr32(cb, 13, src);
            }
            x86_movsxd_rr(cb, 13, 13);
        }
        x86_imul_rr(cb, 10, 13);
        if (ra == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_ra = 13;
        } else {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "SMSUBL");
            if (x86_ra != 13) {
                x86_mov_rr(cb, 13, x86_ra);
            }
            x86_ra = 13;
        }
        x86_sub_rr(cb, x86_ra, 10);
        if (rd != 31u) {
            if (x86_dst != x86_ra) {
                x86_mov_rr(cb, x86_dst, x86_ra);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SMSUBL");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* MADD Xd, Xn, Xm, Xa (MUL alias when Xa==XZR). */
    if ((insn & 0xFFE08000u) == 0x9B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "MADD");
            if (src != 10) {
                x86_mov_rr(cb, 10, src);
            }
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "MADD");
            if (src != 13) {
                x86_mov_rr(cb, 13, src);
            }
        }
        x86_imul_rr(cb, 10, 13);
        if (ra != 31u) {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "MADD");
            x86_add_rr(cb, 10, x86_ra);
        }
        if (rd != 31u) {
            if (x86_dst != 10) {
                x86_mov_rr(cb, x86_dst, 10);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "MADD");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* MSUB Xd, Xn, Xm, Xa (MNEG alias when Xa==XZR). */
    if ((insn & 0xFFE08000u) == 0x9B008000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "MSUB");
            if (src != 10) {
                x86_mov_rr(cb, 10, src);
            }
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "MSUB");
            if (src != 13) {
                x86_mov_rr(cb, 13, src);
            }
        }
        x86_imul_rr(cb, 10, 13);
        if (ra == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_ra = 13;
        } else {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "MSUB");
            if (x86_ra != 13) {
                x86_mov_rr(cb, 13, x86_ra);
            }
            x86_ra = 13;
        }
        x86_sub_rr(cb, x86_ra, 10);
        if (rd != 31u) {
            if (x86_dst != x86_ra) {
                x86_mov_rr(cb, x86_dst, x86_ra);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "MSUB");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* MADD Wd, Wn, Wm, Wa (MUL alias when Wa==WZR). */
    if ((insn & 0xFFE08000u) == 0x1B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "MADD (W)");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "MADD (W)");
            if (src != 13) {
                x86_mov_rr32(cb, 13, src);
            }
        }
        x86_imul_rr32(cb, 10, 13);
        if (ra != 31u) {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "MADD (W)");
            x86_add_rr32(cb, 10, x86_ra);
        }
        if (rd != 31u) {
            if (x86_dst != 10) {
                x86_mov_rr32(cb, x86_dst, 10);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "MADD (W)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* MSUB Wd, Wn, Wm, Wa (MNEG alias when Wa==WZR). */
    if ((insn & 0xFFE08000u) == 0x1B008000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned ra = (insn >> 10) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_ra;
        int x86_dst;
        int src;

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;

        emit_preserve_guest_flags_begin(cb);
        if (rn == 31u) {
            x86_mov_imm64(cb, 10, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rn, 13, pc, "MSUB (W)");
            if (src != 10) {
                x86_mov_rr32(cb, 10, src);
            }
        }
        if (rm == 31u) {
            x86_mov_imm64(cb, 13, 0);
        } else {
            src = materialize_guest_xreg_read(cb, rm, 13, pc, "MSUB (W)");
            if (src != 13) {
                x86_mov_rr32(cb, 13, src);
            }
        }
        x86_imul_rr32(cb, 10, 13);
        if (ra == 31u) {
            x86_mov_imm64(cb, 13, 0);
            x86_ra = 13;
        } else {
            x86_ra = materialize_guest_xreg_read(cb, ra, 13, pc, "MSUB (W)");
            if (x86_ra != 13) {
                x86_mov_rr32(cb, 13, x86_ra);
            }
            x86_ra = 13;
        }
        x86_sub_rr32(cb, x86_ra, 10);
        if (rd != 31u) {
            if (x86_dst != x86_ra) {
                x86_mov_rr32(cb, x86_dst, x86_ra);
            }
            writeback_guest_xreg(cb, rd, x86_dst, pc, "MSUB (W)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ADD Xd, Xn, #imm12{,LSL #12} */
    if ((insn & 0xFF000000u) == 0x91000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADD imm");
        x86_dst = (x86_rd >= 0) ? x86_rd : 10;

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_add_imm32(cb, x86_dst, imm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "ADD imm");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ADD Wd, Wn, #imm12{,LSL #12} */
    if ((insn & 0xFF000000u) == 0x11000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADD (W, imm)");
        x86_dst = (x86_rd >= 0) ? x86_rd : 10;

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_add_imm32_32(cb, x86_dst, imm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "ADD (W, imm)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SUB Xd, Xn, #imm12{,LSL #12} */
    if ((insn & 0xFF000000u) == 0xD1000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUB imm");
        x86_dst = (x86_rd >= 0) ? x86_rd : 10;

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_sub_imm32(cb, x86_dst, imm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "SUB imm");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SUB Wd, Wn, #imm12{,LSL #12} */
    if ((insn & 0xFF000000u) == 0x51000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUB (W, imm)");
        x86_dst = (x86_rd >= 0) ? x86_rd : 10;

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_sub_imm32_32(cb, x86_dst, imm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "SUB (W, imm)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* CMP Xn, #imm12{,LSL #12} (alias SUBS XZR, Xn, #imm12) */
    if ((insn & 0xFF00001Fu) == 0xF100001Fu) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rn;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "CMP imm");

        x86_cmp_imm32(cb, x86_rn, imm);
        return;
    }

    /* CMP Wn, #imm12{,LSL #12} (alias SUBS WZR, Wn, #imm12) */
    if ((insn & 0xFF00001Fu) == 0x7100001Fu) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rn;

        if (sh) {
            imm <<= 12;
        }

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 10, pc, "CMP (W, imm)");
        x86_cmp_imm32_32(cb, x86_rn, imm);
        return;
    }

    /* ADDS Xd, Xn, #imm12{,LSL #12} (CMN alias when Rd==XZR). */
    if ((insn & 0xFF000000u) == 0xB1000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADDS imm");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_add_imm32(cb, x86_dst, imm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ADDS imm");
        }
        return;
    }

    /* ADDS Wd, Wn, #imm12{,LSL #12} (CMN alias when Rd==WZR). */
    if ((insn & 0xFF000000u) == 0x31000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADDS (W, imm)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_add_imm32_32(cb, x86_dst, imm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ADDS (W, imm)");
        }
        return;
    }

    /* SUBS Xd, Xn, #imm12{,LSL #12} (CMP alias when Rd==XZR). */
    if ((insn & 0xFF000000u) == 0xF1000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUBS imm");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_sub_imm32(cb, x86_dst, imm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SUBS imm");
        }
        return;
    }

    /* SUBS Wd, Wn, #imm12{,LSL #12} (CMP alias when Rd==WZR). */
    if ((insn & 0xFF000000u) == 0x71000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm = (insn >> 10) & 0xFFFu;
        unsigned sh = (insn >> 22) & 0x1u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_dst;

        if (sh) {
            imm <<= 12;
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUBS (W, imm)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_sub_imm32_32(cb, x86_dst, imm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SUBS (W, imm)");
        }
        return;
    }

    /*
     * CSINC/CSINV/CSNEG (W/X), plus aliases like CSET/CSETM via ZR operands.
     * Encoding class shared with CSEL:
     *   op = bit30, o2 = bit10, variant = (op<<1)|o2:
     *     1=CSINC, 2=CSINV, 3=CSNEG.
     */
    if ((insn & 0x1FE00800u) == 0x1A800000u) {
        unsigned sf = (insn >> 31) & 1u; /* 0=W, 1=X */
        unsigned op = (insn >> 30) & 1u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned o2 = (insn >> 10) & 1u;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rd = insn & 0x1Fu;
        unsigned variant = (op << 1) | o2;
        int cc = arm_cond_to_x86_cc(cond);
        int x86_rd_map = map_reg(rd);
        int x86_dst;
        int x86_rn;
        int x86_rm;
        bool is_64 = sf != 0u;

        if (variant == 0u) {
            /* CSEL handled below by dedicated blocks. */
        } else {
            if (cond == 0xFu) {
                fprintf(stderr, "CS* cond=NV unsupported at pc=%zu\n", pc);
                exit(1);
            }

            if (rd == 31u) {
                return; /* write-to-ZR form has no architectural effect */
            }

            x86_dst = (x86_rd_map >= 0) ? x86_rd_map : 10;
            x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CS*");

            if (cond == 0xEu) { /* AL */
                if (x86_dst != x86_rn) {
                    if (is_64) {
                        x86_mov_rr(cb, x86_dst, x86_rn);
                    } else {
                        x86_mov_rr32(cb, x86_dst, x86_rn);
                    }
                }
                if (x86_rd_map < 0) {
                    writeback_guest_xreg(cb, rd, x86_dst, pc, "CS*");
                }
                return;
            }

            x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CS*");
            if (x86_dst != x86_rm) {
                if (is_64) {
                    x86_mov_rr(cb, x86_dst, x86_rm);
                } else {
                    x86_mov_rr32(cb, x86_dst, x86_rm);
                }
            }

            switch (variant) {
                case 1: /* CSINC: false path uses (Rm + 1) */
                    emit_preserve_guest_flags_begin(cb);
                    if (is_64) {
                        x86_add_imm32(cb, x86_dst, 1);
                    } else {
                        x86_add_imm32_32(cb, x86_dst, 1);
                    }
                    emit_preserve_guest_flags_end(cb);
                    break;
                case 2: /* CSINV: false path uses ~Rm */
                    if (is_64) {
                        x86_not_r(cb, x86_dst);
                    } else {
                        x86_not_r32(cb, x86_dst);
                    }
                    break;
                case 3: /* CSNEG: false path uses -Rm = ~Rm + 1 */
                    emit_preserve_guest_flags_begin(cb);
                    if (is_64) {
                        x86_not_r(cb, x86_dst);
                        x86_add_imm32(cb, x86_dst, 1);
                    } else {
                        x86_not_r32(cb, x86_dst);
                        x86_add_imm32_32(cb, x86_dst, 1);
                    }
                    emit_preserve_guest_flags_end(cb);
                    break;
                default:
                    fprintf(stderr, "internal invalid CS* variant at pc=%zu\n", pc);
                    exit(1);
            }

            if (x86_dst != x86_rn) {
                if (is_64) {
                    x86_cmovcc_rr(cb, x86_dst, x86_rn, (uint8_t)cc);
                } else {
                    x86_cmovcc_rr32(cb, x86_dst, x86_rn, (uint8_t)cc);
                }
            }
            if (x86_rd_map < 0) {
                writeback_guest_xreg(cb, rd, x86_dst, pc, "CS*");
            }
            return;
        }
    }

    /* CSEL Xd, Xn, Xm, <cond> */
    if ((insn & 0xFFE00C00u) == 0x9A800000u) {
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rd = insn & 0x1Fu;
        int x86_rm;
        int x86_rn;
        int x86_rd = map_reg(rd);
        int x86_dst;
        int cc = arm_cond_to_x86_cc(cond);

        if (cond == 0xF) {
            fprintf(stderr, "CSEL cond=NV unsupported at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write-to-XZR form has no architectural effect */
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 10;
        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CSEL");

        if (cond == 0xE) { /* AL */
            if (x86_dst != x86_rn) {
                x86_mov_rr(cb, x86_dst, x86_rn);
            }
            if (x86_rd < 0) {
                writeback_guest_xreg(cb, rd, x86_dst, pc, "CSEL");
            }
            return;
        }

        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CSEL");
        if (x86_dst != x86_rm) {
            x86_mov_rr(cb, x86_dst, x86_rm);
        }
        if (x86_dst != x86_rn) {
            x86_cmovcc_rr(cb, x86_dst, x86_rn, (uint8_t)cc);
        }
        if (x86_rd < 0) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "CSEL");
        }
        return;
    }

    /* CSEL Wd, Wn, Wm, <cond> */
    if ((insn & 0xFFE00C00u) == 0x1A800000u) {
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rd = insn & 0x1Fu;
        int x86_rm;
        int x86_rn;
        int x86_rd = map_reg(rd);
        int x86_dst;
        int cc = arm_cond_to_x86_cc(cond);

        if (cond == 0xF) {
            fprintf(stderr, "CSEL (W) cond=NV unsupported at pc=%zu\n", pc);
            exit(1);
        }
        if (rd == 31u) {
            return; /* write-to-WZR form has no architectural effect */
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 10;
        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CSEL (W)");

        if (cond == 0xE) { /* AL */
            if (x86_dst != x86_rn) {
                x86_mov_rr32(cb, x86_dst, x86_rn);
            }
            if (x86_rd < 0) {
                writeback_guest_xreg(cb, rd, x86_dst, pc, "CSEL (W)");
            }
            return;
        }

        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CSEL (W)");
        if (x86_dst != x86_rm) {
            x86_mov_rr32(cb, x86_dst, x86_rm);
        }
        if (x86_dst != x86_rn) {
            x86_cmovcc_rr32(cb, x86_dst, x86_rn, (uint8_t)cc);
        }
        if (x86_rd < 0) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "CSEL (W)");
        }
        return;
    }

    /* MOVI Vd.{8B,16B}, #imm8 */
    if ((insn & 0xBFF8FC00u) == 0x0F00E400u) {
        unsigned q = (insn >> 30) & 1u;
        unsigned imm8 = (((insn >> 16) & 0x7u) << 5) | ((insn >> 5) & 0x1Fu);
        unsigned rd = insn & 0x1Fu;
        uint64_t pattern = 0x0101010101010101ull * (uint64_t)imm8;

        emit_preserve_guest_flags_begin(cb);
        x86_mov_imm64(cb, 10, pattern);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 0), 10);
        if (q) {
            x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 1), 10);
        } else {
            x86_mov_imm64(cb, 10, 0);
            x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 1), 10);
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /*
     * MOVI Vd.2D, #imm (subset used in current APK corpus):
     * support #0 and #-1 forms.
     */
    if ((insn & 0xBFF8FC00u) == 0x2F00E400u && ((insn >> 30) & 1u) == 1u && ((insn >> 29) & 1u) == 1u) {
        unsigned imm8 = (((insn >> 16) & 0x7u) << 5) | ((insn >> 5) & 0x1Fu);
        unsigned rd = insn & 0x1Fu;
        uint64_t pattern;

        if (imm8 == 0u) {
            pattern = 0;
        } else if (imm8 == 0xFFu) {
            pattern = UINT64_MAX;
        } else {
            fprintf(stderr, "unsupported MOVI (2D immediate variant) at pc=%zu\n", pc);
            exit(1);
        }

        emit_preserve_guest_flags_begin(cb);
        x86_mov_imm64(cb, 10, pattern);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 0), 10);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 1), 10);
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SQRDMLAH/SQRDMLSH Vd.{2S,4S}, Vn.{2S,4S}, Vm.{2S,4S} */
    {
        uint32_t sqrdml_tag = insn & 0xBFE0FC00u;
        if (sqrdml_tag == 0x2E808400u || sqrdml_tag == 0x0EA08400u || sqrdml_tag == 0x2EA08400u) {
            bool is_sub = (sqrdml_tag == 0x0EA08400u || sqrdml_tag == 0x2EA08400u);
            unsigned q = (insn >> 30) & 1u;
            unsigned rm = (insn >> 16) & 0x1Fu;
            unsigned rn = (insn >> 5) & 0x1Fu;
            unsigned rd = insn & 0x1Fu;

            emit_preserve_guest_flags_begin(cb);
            if (is_sub) {
                emit_sqrdmlsh_lane32(cb, rd, rn, rm, 0u, 0u);
                emit_sqrdmlsh_lane32(cb, rd, rn, rm, 0u, 1u);
            } else {
                emit_sqrdmlah_lane32(cb, rd, rn, rm, 0u, 0u);
                emit_sqrdmlah_lane32(cb, rd, rn, rm, 0u, 1u);
            }
            if (q) {
                if (is_sub) {
                    emit_sqrdmlsh_lane32(cb, rd, rn, rm, 1u, 0u);
                    emit_sqrdmlsh_lane32(cb, rd, rn, rm, 1u, 1u);
                } else {
                    emit_sqrdmlah_lane32(cb, rd, rn, rm, 1u, 0u);
                    emit_sqrdmlah_lane32(cb, rd, rn, rm, 1u, 1u);
                }
            } else {
                /* 2S form zeros the upper 64 bits of destination. */
                x86_mov_imm64(cb, 10, 0);
                x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 1), 10);
            }
            emit_preserve_guest_flags_end(cb);
            return;
        }
    }

    /* AND/BIC/ORR/EOR Vd.{8B,16B}, Vn.{8B,16B}, Vm.{8B,16B} */
    if ((insn & 0xBFE0FC00u) == 0x0E201C00u || (insn & 0xBFE0FC00u) == 0x0E601C00u ||
        (insn & 0xBFE0FC00u) == 0x0EA01C00u || (insn & 0xBFE0FC00u) == 0x2E201C00u) {
        unsigned q = (insn >> 30) & 1u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rd = insn & 0x1Fu;
        uint32_t simd_logic_tag = insn & 0xBFE0FC00u;

        emit_preserve_guest_flags_begin(cb);

        /* Low 64-bit lane. */
        x86_mov_r_from_mem_base_disp32(cb, 10, 3, state_v_qword_offset(rn, 0));
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rm, 0));
        switch (simd_logic_tag) {
            case 0x0E201C00u: /* AND */
                x86_and_rr(cb, 10, 13);
                break;
            case 0x0E601C00u: /* BIC = Rn & ~Rm */
                x86_not_r(cb, 13);
                x86_and_rr(cb, 10, 13);
                break;
            case 0x0EA01C00u: /* ORR */
                x86_or_rr(cb, 10, 13);
                break;
            case 0x2E201C00u: /* EOR */
                x86_xor_rr(cb, 10, 13);
                break;
            default:
                fprintf(stderr, "internal unsupported SIMD logical opcode tag 0x%08" PRIx32 " at pc=%zu\n",
                        simd_logic_tag, pc);
                exit(1);
        }
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 0), 10);

        if (q) {
            /* High 64-bit lane for 16B form. */
            x86_mov_r_from_mem_base_disp32(cb, 10, 3, state_v_qword_offset(rn, 1));
            x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rm, 1));
            switch (simd_logic_tag) {
                case 0x0E201C00u: /* AND */
                    x86_and_rr(cb, 10, 13);
                    break;
                case 0x0E601C00u: /* BIC = Rn & ~Rm */
                    x86_not_r(cb, 13);
                    x86_and_rr(cb, 10, 13);
                    break;
                case 0x0EA01C00u: /* ORR */
                    x86_or_rr(cb, 10, 13);
                    break;
                case 0x2E201C00u: /* EOR */
                    x86_xor_rr(cb, 10, 13);
                    break;
                default:
                    fprintf(stderr, "internal unsupported SIMD logical opcode tag 0x%08" PRIx32 " at pc=%zu\n",
                            simd_logic_tag, pc);
                    exit(1);
            }
            x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 1), 10);
        } else {
            /* 8B form clears upper 64 bits of destination vector register. */
            x86_mov_imm64(cb, 10, 0);
            x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rd, 1), 10);
        }

        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* STR Dt, [Xn|SP, #imm12*8] */
    if ((insn & 0xFFC00000u) == 0xFD000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 8u);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STR (D)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp);
        return;
    }

    /* LDR Dt, [Xn|SP, #imm12*8] */
    if ((insn & 0xFFC00000u) == 0xFD400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 8u);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDR (D)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        return;
    }

    /* STR St, [Xn|SP, #imm12*4] */
    if ((insn & 0xFFC00000u) == 0xBD000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 4u);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STR (S)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, 13, disp);
        return;
    }

    /* LDR St, [Xn|SP, #imm12*4] */
    if ((insn & 0xFFC00000u) == 0xBD400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 4u);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDR (S)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp);
        x86_mov_mem_base_disp32_from_r32(cb, 3, 13, state_v_qword_offset(rt, 0));
        return;
    }

    /* STR Qt, [Xn|SP, #imm12*16] */
    if ((insn & 0xFFC00000u) == 0x3D800000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 16u);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STR (Q)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp + 8);
        return;
    }

    /* LDR Qt, [Xn|SP, #imm12*16] */
    if ((insn & 0xFFC00000u) == 0x3DC00000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 16u);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDR (Q)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp + 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 1), 13);
        return;
    }

    /* STR Dt, [Xn|SP], #simm9 / [Xn|SP, #simm9]! (post/pre-index) */
    if ((insn & 0xFFE00C00u) == 0xFC000400u || (insn & 0xFFE00C00u) == 0xFC000C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STR (D, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (D, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 0);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (D, post/pre-index)");
        }
        return;
    }

    /* LDR Dt, [Xn|SP], #simm9 / [Xn|SP, #simm9]! (post/pre-index) */
    if ((insn & 0xFFE00C00u) == 0xFC400400u || (insn & 0xFFE00C00u) == 0xFC400C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDR (D, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (D, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (D, post/pre-index)");
        }
        return;
    }

    /* STR St, [Xn|SP], #simm9 / [Xn|SP, #simm9]! (post/pre-index) */
    if ((insn & 0xFFE00C00u) == 0xBC000400u || (insn & 0xFFE00C00u) == 0xBC000C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STR (S, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (S, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, 13, 0);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (S, post/pre-index)");
        }
        return;
    }

    /* LDR St, [Xn|SP], #simm9 / [Xn|SP, #simm9]! (post/pre-index) */
    if ((insn & 0xFFE00C00u) == 0xBC400400u || (insn & 0xFFE00C00u) == 0xBC400C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDR (S, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (S, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 0);
        x86_mov_mem_base_disp32_from_r32(cb, 3, 13, state_v_qword_offset(rt, 0));
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (S, post/pre-index)");
        }
        return;
    }

    /* STR Qt, [Xn|SP], #simm9 / [Xn|SP, #simm9]! (post/pre-index) */
    if ((insn & 0xFFE00C00u) == 0x3C800400u || (insn & 0xFFE00C00u) == 0x3C800C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STR (Q, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (Q, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 0);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 8);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (Q, post/pre-index)");
        }
        return;
    }

    /* LDR Qt, [Xn|SP], #simm9 / [Xn|SP, #simm9]! (post/pre-index) */
    if ((insn & 0xFFE00C00u) == 0x3CC00400u || (insn & 0xFFE00C00u) == 0x3CC00C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDR (Q, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (Q, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 1), 13);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (Q, post/pre-index)");
        }
        return;
    }

    /* STUR Qt, [Xn|SP, #simm9] */
    if ((insn & 0xFFC00000u) == 0x3C800000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STUR (Q)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, simm9);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, simm9 + 8);
        return;
    }

    /* LDUR Qt, [Xn|SP, #simm9] */
    if ((insn & 0xFFC00000u) == 0x3CC00000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDUR (Q)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, simm9);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, simm9 + 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 1), 13);
        return;
    }

    /* STUR Dt, [Xn|SP, #simm9] */
    if ((insn & 0xFFC00000u) == 0xFC000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STUR (D)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, simm9);
        return;
    }

    /* LDUR Dt, [Xn|SP, #simm9] */
    if ((insn & 0xFFC00000u) == 0xFC400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDUR (D)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, simm9);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        return;
    }

    /* STUR St, [Xn|SP, #simm9] */
    if ((insn & 0xFFC00000u) == 0xBC000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STUR (S)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, 13, simm9);
        return;
    }

    /* LDUR St, [Xn|SP, #simm9] */
    if ((insn & 0xFFC00000u) == 0xBC400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDUR (S)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_index_disp32(cb, 13, 10, x86_rn, simm9);
        x86_mov_mem_base_disp32_from_r32(cb, 3, 13, state_v_qword_offset(rt, 0));
        return;
    }

    /* STP Dt1, Dt2, [Xn|SP, #imm7*8] (signed offset) */
    if ((insn & 0xFFC00000u) == 0x6D000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 8;
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STP (D)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt2, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp + 8);
        return;
    }

    /* LDP Dt1, Dt2, [Xn|SP, #imm7*8] (signed offset) */
    if ((insn & 0xFFC00000u) == 0x6D400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 8;
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDP (D)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp + 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt2, 0), 13);
        return;
    }

    /* STP Qt1, Qt2, [Xn|SP], #imm7*16 / [Xn|SP, #imm7*16]! (post/pre-index) */
    if ((insn & 0xFFC00000u) == 0xAC800000u || (insn & 0xFFC00000u) == 0xAD800000u) {
        bool is_pre = (insn & 0x01000000u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 16;
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STP (Q, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "STP (Q, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 32, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 0);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 8);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt2, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 16);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt2, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, 24);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "STP (Q, post/pre-index)");
        }
        return;
    }

    /* LDP Qt1, Qt2, [Xn|SP], #imm7*16 / [Xn|SP, #imm7*16]! (post/pre-index) */
    if ((insn & 0xFFC00000u) == 0xACC00000u || (insn & 0xFFC00000u) == 0xADC00000u) {
        bool is_pre = (insn & 0x01000000u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 16;
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDP (Q, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "LDP (Q, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 32, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 0);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 1), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 16);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt2, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, 24);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt2, 1), 13);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "LDP (Q, post/pre-index)");
        }
        return;
    }

    /* STP Qt1, Qt2, [Xn|SP, #imm7*16] (signed offset) */
    if ((insn & 0xFFC00000u) == 0xAD000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 16;
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "STP (Q)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 32, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp + 8);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt2, 0));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp + 16);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_v_qword_offset(rt2, 1));
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, 13, disp + 24);
        return;
    }

    /* LDP Qt1, Qt2, [Xn|SP, #imm7*16] (signed offset) */
    if ((insn & 0xFFC00000u) == 0xAD400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 16;
        int x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 12, pc, "LDP (Q)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 32, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp + 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt, 1), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp + 16);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt2, 0), 13);
        x86_mov_r_from_mem_base_index_disp32(cb, 13, 10, x86_rn, disp + 24);
        x86_mov_mem_base_disp32_from_r(cb, 3, state_v_qword_offset(rt2, 1), 13);
        return;
    }

    /* STP Xt1, Xt2, [Xn], #imm7*8 / [Xn, #imm7*8]! (post/pre-index, 64-bit) */
    if ((insn & 0xFFC00000u) == 0xA8800000u || (insn & 0xFFC00000u) == 0xA9800000u) {
        bool is_pre = (insn & 0x01000000u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 8;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;

        if (rn != 31u && (rn == rt || rn == rt2)) {
            fprintf(stderr, "unsupported writeback alias of STP (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STP (post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "STP (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STP (post/pre-index)");
        }
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, 0);
        if (x86_rt2 < 0) {
            x86_rt2 = materialize_guest_xreg_or_zr_read(cb, rt2, 12, pc, "STP (post/pre-index)");
        }
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt2, 8);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "STP (post/pre-index)");
        }
        return;
    }

    /* LDP Xt1, Xt2, [Xn], #imm7*8 / [Xn, #imm7*8]! (post/pre-index, 64-bit) */
    if ((insn & 0xFFC00000u) == 0xA8C00000u || (insn & 0xFFC00000u) == 0xA9C00000u) {
        bool is_pre = (insn & 0x01000000u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 8;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && (rn == rt || rn == rt2)) {
            fprintf(stderr, "unsupported writeback alias of LDP (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDP (post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "LDP (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDP (post/pre-index)");
        }
        x86_dst = (x86_rt2 >= 0) ? x86_rt2 : 12;
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 8);
        if (x86_rt2 < 0) {
            writeback_guest_xreg_unless_zr(cb, rt2, x86_dst, pc, "LDP (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "LDP (post/pre-index)");
        }
        return;
    }

    /* STP Wt1, Wt2, [Xn], #imm7*4 / [Xn, #imm7*4]! (post/pre-index, 32-bit) */
    if ((insn & 0xFFC00000u) == 0x28800000u || (insn & 0xFFC00000u) == 0x29800000u) {
        bool is_pre = (insn & 0x01000000u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 4;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;

        if (rn != 31u && (rn == rt || rn == rt2)) {
            fprintf(stderr, "unsupported writeback alias of STP (W, post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STP (W, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "STP (W, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STP (W, post/pre-index)");
        }
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt, 0);
        if (x86_rt2 < 0) {
            x86_rt2 = materialize_guest_xreg_or_zr_read(cb, rt2, 12, pc, "STP (W, post/pre-index)");
        }
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt2, 4);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "STP (W, post/pre-index)");
        }
        return;
    }

    /* LDP Wt1, Wt2, [Xn], #imm7*4 / [Xn, #imm7*4]! (post/pre-index, 32-bit) */
    if ((insn & 0xFFC00000u) == 0x28C00000u || (insn & 0xFFC00000u) == 0x29C00000u) {
        bool is_pre = (insn & 0x01000000u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 4;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && (rn == rt || rn == rt2)) {
            fprintf(stderr, "unsupported writeback alias of LDP (W, post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDP (W, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "LDP (W, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDP (W, post/pre-index)");
        }
        x86_dst = (x86_rt2 >= 0) ? x86_rt2 : 12;
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 4);
        if (x86_rt2 < 0) {
            writeback_guest_xreg_unless_zr(cb, rt2, x86_dst, pc, "LDP (W, post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, disp, pc, "LDP (W, post/pre-index)");
        }
        return;
    }

    /* STP Xt1, Xt2, [Xn, #imm7*8] (signed offset, 64-bit) */
    if ((insn & 0xFFC00000u) == 0xA9000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 8;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STP");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STP");
        }
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, disp);
        if (x86_rt2 < 0) {
            x86_rt2 = materialize_guest_xreg_or_zr_read(cb, rt2, 12, pc, "STP");
        }
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt2, disp + 8);
        return;
    }

    /* LDP Xt1, Xt2, [Xn, #imm7*8] (signed offset, 64-bit) */
    if ((insn & 0xFFC00000u) == 0xA9400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 8;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDP");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 16, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDP");
        }
        x86_dst = (x86_rt2 >= 0) ? x86_rt2 : 12;
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, disp + 8);
        if (x86_rt2 < 0) {
            writeback_guest_xreg_unless_zr(cb, rt2, x86_dst, pc, "LDP");
        }
        return;
    }

    /* STP Wt1, Wt2, [Xn, #imm7*4] (signed offset, 32-bit) */
    if ((insn & 0xFFC00000u) == 0x29000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 4;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STP (W)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STP (W)");
        }
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt, disp);
        if (x86_rt2 < 0) {
            x86_rt2 = materialize_guest_xreg_or_zr_read(cb, rt2, 12, pc, "STP (W)");
        }
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt2, disp + 4);
        return;
    }

    /* LDP Wt1, Wt2, [Xn, #imm7*4] (signed offset, 32-bit) */
    if ((insn & 0xFFC00000u) == 0x29400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rt2 = (insn >> 10) & 0x1Fu;
        int32_t simm7 = sign_extend32((insn >> 15) & 0x7Fu, 7);
        int32_t disp = simm7 * 4;
        int x86_rt = map_reg(rt);
        int x86_rt2 = map_reg(rt2);
        int x86_rn;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDP (W)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDP (W)");
        }
        x86_dst = (x86_rt2 >= 0) ? x86_rt2 : 12;
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, disp + 4);
        if (x86_rt2 < 0) {
            writeback_guest_xreg_unless_zr(cb, rt2, x86_dst, pc, "LDP (W)");
        }
        return;
    }

    /* Post/pre-index forms (writeback) for single-register memory ops. */
    if ((insn & 0xFFE00C00u) == 0xF8000400u || (insn & 0xFFE00C00u) == 0xF8000C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of STR (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STR (post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 8, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STR (post/pre-index)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, 0);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0xF8400400u || (insn & 0xFFE00C00u) == 0xF8400C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDR (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDR (post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDR (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0xB8000400u || (insn & 0xFFE00C00u) == 0xB8000C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of STR (W, post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STR (W, post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (W, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 4, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STR (W, post/pre-index)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt, 0);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STR (W, post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0xB8400400u || (insn & 0xFFE00C00u) == 0xB8400C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDR (W, post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDR (W, post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (W, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDR (W, post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDR (W, post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x38000400u || (insn & 0xFFE00C00u) == 0x38000C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of STRB (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STRB (post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STRB (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 1, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STRB (post/pre-index)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem8_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, 0);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STRB (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x38400400u || (insn & 0xFFE00C00u) == 0x38400C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDRB (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRB (post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRB (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 1, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRB (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRB (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x38C00400u || (insn & 0xFFE00C00u) == 0x38C00C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDRSB (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSB (post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSB (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 1, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movsx_r64_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSB (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSB (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x78000400u || (insn & 0xFFE00C00u) == 0x78000C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of STRH (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STRH (post/pre-index)");

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STRH (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 2, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STRH (post/pre-index)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem16_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, 0);
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "STRH (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x78400400u || (insn & 0xFFE00C00u) == 0x78400C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDRH (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRH (post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRH (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRH (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRH (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x78C00400u || (insn & 0xFFE00C00u) == 0x78C00C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDRSH (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSH (post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSH (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movsx_r64_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSH (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSH (post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0x78800400u || (insn & 0xFFE00C00u) == 0x78800C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDRSH (W, post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSH (W, post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSH (W, post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movsx_r64_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        x86_mov_rr32(cb, x86_dst, x86_dst);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSH (W, post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSH (W, post/pre-index)");
        }
        return;
    }

    if ((insn & 0xFFE00C00u) == 0xB8800400u || (insn & 0xFFE00C00u) == 0xB8800C00u) {
        bool is_pre = (insn & 0x800u) != 0;
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;

        if (rn != 31u && rt == rn) {
            fprintf(stderr, "unsupported writeback alias of LDRSW (post/pre-index) at pc=%zu\n", pc);
            exit(1);
        }
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSW (post/pre-index)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        if (is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSW (post/pre-index)");
        }
        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, 0, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movsxd_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSW (post/pre-index)");
        }
        if (!is_pre) {
            emit_writeback_add_signed_imm_guest(cb, rn, x86_rn, simm9, pc, "LDRSW (post/pre-index)");
        }
        return;
    }

    /* STR Wt, [Xn|SP, Rm{, <extend> {#2}}] (register offset) */
    if ((insn & 0xFFE00800u) == 0xB8200800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STR (W, regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "STR (W, regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 4, pc,
                                                    "STR (W, regoff)");
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STR (W, regoff)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_addr, x86_rt, 0);
        return;
    }

    /* LDR Wt, [Xn|SP, Rm{, <extend> {#2}}] (register offset) */
    if ((insn & 0xFFE00800u) == 0xB8600800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDR (W, regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "LDR (W, regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 4, pc,
                                                    "LDR (W, regoff)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_addr, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDR (W, regoff)");
        }
        return;
    }

    /* STR Xt, [Xn|SP, Rm{, <extend> {#3}}] (register offset) */
    if ((insn & 0xFFE00800u) == 0xF8200800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STR (X, regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "STR (X, regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 8, pc,
                                                    "STR (X, regoff)");
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STR (X, regoff)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_addr, x86_rt, 0);
        return;
    }

    /* LDR Xt, [Xn|SP, Rm{, <extend> {#3}}] (register offset) */
    if ((insn & 0xFFE00800u) == 0xF8600800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDR (X, regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "LDR (X, regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 8, pc,
                                                    "LDR (X, regoff)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_addr, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDR (X, regoff)");
        }
        return;
    }

    /* STRH Wt, [Xn|SP, Rm{, <extend> {#1}}] (register offset) */
    if ((insn & 0xFFE00800u) == 0x78200800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STRH (regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "STRH (regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 2, pc,
                                                    "STRH (regoff)");
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STRH (regoff)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem16_base_index_disp32_from_r(cb, 10, x86_addr, x86_rt, 0);
        return;
    }

    /* LDRH Wt, [Xn|SP, Rm{, <extend> {#1}}] (register offset) */
    if ((insn & 0xFFE00800u) == 0x78600800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRH (regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "LDRH (regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 2, pc,
                                                    "LDRH (regoff)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_addr, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRH (regoff)");
        }
        return;
    }

    /* STRB Wt, [Xn|SP, Rm{, <extend>}] (register offset) */
    if ((insn & 0xFFE00800u) == 0x38200800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STRB (regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "STRB (regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 1, pc,
                                                    "STRB (regoff)");
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STRB (regoff)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_mov_mem8_base_index_disp32_from_r(cb, 10, x86_addr, x86_rt, 0);
        return;
    }

    /* LDRB Wt, [Xn|SP, Rm{, <extend>}] (register offset) */
    if ((insn & 0xFFE00800u) == 0x38600800u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned s = (insn >> 12) & 0x1u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        int x86_addr;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRB (regoff)");
        if (rm == 31u) {
            x86_mov_imm64(cb, 10, 0);
            x86_rm = 10;
        } else {
            x86_rm = materialize_guest_xreg_read(cb, rm, 10, pc, "LDRB (regoff)");
        }
        x86_addr = materialize_guest_mem_reg_offset(cb, oob_patches, x86_rn, x86_rm, option, s, 1, pc,
                                                    "LDRB (regoff)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem);
        x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_addr, 0);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRB (regoff)");
        }
        return;
    }

    /* STURB Wt, [Xn, #simm9] (unscaled, 8-bit) */
    if ((insn & 0xFFE00C00u) == 0x38000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STURB");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 1, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STURB");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem8_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, simm9);
        return;
    }

    /* LDURB Wt, [Xn, #simm9] (unscaled, 8-bit) */
    if ((insn & 0xFFE00C00u) == 0x38400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDURB");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 1, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDURB");
        }
        return;
    }

    /* LDURSB Xt, [Xn, #simm9] (unscaled, sign-extend byte) */
    if ((insn & 0xFFE00C00u) == 0x38C00000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDURSB");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 1, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsx_r64_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDURSB");
        }
        return;
    }

    /* STURH Wt, [Xn, #simm9] (unscaled, 16-bit) */
    if ((insn & 0xFFE00C00u) == 0x78000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STURH");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 2, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STURH");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem16_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, simm9);
        return;
    }

    /* LDURH Wt, [Xn, #simm9] (unscaled, 16-bit) */
    if ((insn & 0xFFE00C00u) == 0x78400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDURH");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDURH");
        }
        return;
    }

    /* LDURSH Xt, [Xn, #simm9] (unscaled, sign-extend halfword) */
    if ((insn & 0xFFE00C00u) == 0x78C00000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDURSH");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsx_r64_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDURSH");
        }
        return;
    }

    /* LDURSH Wt, [Xn, #simm9] (unscaled, sign-extend halfword) */
    if ((insn & 0xFFE00C00u) == 0x78800000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDURSH (W)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsx_r64_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        x86_mov_rr32(cb, x86_dst, x86_dst);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDURSH (W)");
        }
        return;
    }

    /* LDURSW Xt, [Xn, #simm9] (unscaled, sign-extend word) */
    if ((insn & 0xFFE00C00u) == 0xB8800000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDURSW");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsxd_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDURSW");
        }
        return;
    }

    /* LDUR Xt, [Xn, #simm9] (unscaled, 64-bit) */
    if ((insn & 0xFFE00C00u) == 0xF8400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDUR");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDUR");
        }
        return;
    }

    /* STUR Xt, [Xn, #simm9] (unscaled, 64-bit) */
    if ((insn & 0xFFE00C00u) == 0xF8000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STUR");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 8, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STUR");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, simm9);
        return;
    }

    /* LDUR Wt, [Xn, #simm9] (unscaled, 32-bit) */
    if ((insn & 0xFFE00C00u) == 0xB8400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDUR (W)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, simm9);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDUR (W)");
        }
        return;
    }

    /* STUR Wt, [Xn, #simm9] (unscaled, 32-bit) */
    if ((insn & 0xFFE00C00u) == 0xB8000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t simm9 = sign_extend32((insn >> 12) & 0x1FFu, 9);
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STUR (W)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, simm9, 4, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STUR (W)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt, simm9);
        return;
    }

    /* LDR Xt, [Xn, #imm12] (unsigned immediate, 64-bit) */
    if ((insn & 0xFFC00000u) == 0xF9400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        uint32_t disp = imm12 * 8u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDR");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 8, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, (int32_t)disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDR");
        }
        return;
    }

    /* STR Xt, [Xn, #imm12] (unsigned immediate, 64-bit) */
    if ((insn & 0xFFC00000u) == 0xF9000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        uint32_t disp = imm12 * 8u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STR");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 8, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STR");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, (int32_t)disp);
        return;
    }

    /* LDR Wt, [Xn, #imm12] (unsigned immediate, 32-bit) */
    if ((insn & 0xFFC00000u) == 0xB9400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        uint32_t disp = imm12 * 4u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDR (W)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_r32_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, (int32_t)disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDR (W)");
        }
        return;
    }

    /* STR Wt, [Xn, #imm12] (unsigned immediate, 32-bit) */
    if ((insn & 0xFFC00000u) == 0xB9000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        uint32_t disp = imm12 * 4u;
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STR (W)");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 4, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STR (W)");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem_base_index_disp32_from_r32(cb, 10, x86_rn, x86_rt, (int32_t)disp);
        return;
    }

    /* STRB Wt, [Xn, #imm12] (unsigned immediate, 8-bit) */
    if ((insn & 0xFFC00000u) == 0x39000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)imm12;
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STRB");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 1, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STRB");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem8_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, disp);
        return;
    }

    /* LDRB Wt, [Xn, #imm12] (unsigned immediate, 8-bit) */
    if ((insn & 0xFFC00000u) == 0x39400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)imm12;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRB");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 1, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movzx_r32_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRB");
        }
        return;
    }

    /* LDRSB Xt, [Xn, #imm12] (unsigned immediate, sign-extend byte) */
    if ((insn & 0xFFC00000u) == 0x39C00000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)imm12;
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSB");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 1, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsx_r64_from_mem8_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSB");
        }
        return;
    }

    /* STRH Wt, [Xn, #imm12] (unsigned immediate, 16-bit) */
    if ((insn & 0xFFC00000u) == 0x79000000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 2u);
        int x86_rt = map_reg(rt);
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "STRH");

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 2, pc);
        if (x86_rt < 0) {
            x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 12, pc, "STRH");
        }
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_mov_mem16_base_index_disp32_from_r(cb, 10, x86_rn, x86_rt, disp);
        return;
    }

    /* LDRH Wt, [Xn, #imm12] (unsigned immediate, 16-bit) */
    if ((insn & 0xFFC00000u) == 0x79400000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 2u);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRH");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movzx_r32_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRH");
        }
        return;
    }

    /* LDRSH Xt, [Xn, #imm12] (unsigned immediate, sign-extend halfword) */
    if ((insn & 0xFFC00000u) == 0x79C00000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 2u);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSH");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsx_r64_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSH");
        }
        return;
    }

    /* LDRSH Wt, [Xn, #imm12] (unsigned immediate, sign-extend halfword) */
    if ((insn & 0xFFC00000u) == 0x79800000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 2u);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSH (W)");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 2, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsx_r64_from_mem16_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        x86_mov_rr32(cb, x86_dst, x86_dst);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSH (W)");
        }
        return;
    }

    /* LDRSW Xt, [Xn, #imm12] (unsigned immediate, sign-extend word) */
    if ((insn & 0xFFC00000u) == 0xB9800000u) {
        unsigned rt = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        uint32_t imm12 = (insn >> 10) & 0xFFFu;
        int32_t disp = (int32_t)(imm12 * 4u);
        int x86_rt = map_reg(rt);
        int x86_rn;
        int x86_dst;
        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "LDRSW");
        x86_dst = (x86_rt >= 0) ? x86_rt : 12;

        emit_guest_mem_bounds_check(cb, oob_patches, x86_rn, disp, 4, pc);
        x86_mov_imm64(cb, 10, (uint64_t)(uintptr_t)guest_mem); /* r10 = guest base */
        x86_movsxd_r_from_mem_base_index_disp32(cb, x86_dst, 10, x86_rn, disp);
        if (x86_rt < 0) {
            writeback_guest_xreg_unless_zr(cb, rt, x86_dst, pc, "LDRSW");
        }
        return;
    }

    /* ADD Xd, Xn, Rm{,<extend>{#amount}} (extended register) */
    if ((insn & 0xFFE00000u) == 0x8B200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADD reg-extended");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ADD reg-extended");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, false, pc, "ADD reg-extended");
        x86_add_rr(cb, x86_dst, x86_rm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "ADD reg-extended");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ADD Wd, Wn, Wm{,<extend>{#amount}} (extended register) */
    if ((insn & 0xFFE00000u) == 0x0B200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADD (W, reg-extended)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ADD (W, reg-extended)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, true, pc, "ADD (W, reg-extended)");
        x86_add_rr32(cb, x86_dst, x86_rm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "ADD (W, reg-extended)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SUB Xd, Xn, Rm{,<extend>{#amount}} (extended register) */
    if ((insn & 0xFFE00000u) == 0xCB200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUB reg-extended");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "SUB reg-extended");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, false, pc, "SUB reg-extended");
        x86_sub_rr(cb, x86_dst, x86_rm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "SUB reg-extended");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SUB Wd, Wn, Wm{,<extend>{#amount}} (extended register) */
    if ((insn & 0xFFE00000u) == 0x4B200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUB (W, reg-extended)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "SUB (W, reg-extended)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, true, pc, "SUB (W, reg-extended)");
        x86_sub_rr32(cb, x86_dst, x86_rm);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "SUB (W, reg-extended)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ADDS Xd, Xn, Rm{,<extend>{#amount}} (CMN alias when Rd==XZR). */
    if ((insn & 0xFFE00000u) == 0xAB200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ADDS reg-extended");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ADDS reg-extended");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, false, pc, "ADDS reg-extended");
        x86_add_rr(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ADDS reg-extended");
        }
        return;
    }

    /* ADDS Wd, Wn, Wm{,<extend>{#amount}} (CMN alias when Rd==WZR). */
    if ((insn & 0xFFE00000u) == 0x2B200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ADDS (W, reg-extended)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ADDS (W, reg-extended)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, true, pc, "ADDS (W, reg-extended)");
        x86_add_rr32(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ADDS (W, reg-extended)");
        }
        return;
    }

    /* SUBS Xd, Xn, Rm{,<extend>{#amount}} (CMP alias when Rd==XZR). */
    if ((insn & 0xFFE00000u) == 0xEB200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "SUBS reg-extended");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "SUBS reg-extended");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, false, pc, "SUBS reg-extended");
        x86_sub_rr(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SUBS reg-extended");
        }
        return;
    }

    /* SUBS Wd, Wn, Wm{,<extend>{#amount}} (CMP alias when Rd==WZR). */
    if ((insn & 0xFFE00000u) == 0x6B200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm3 = (insn >> 10) & 0x7u;
        unsigned option = (insn >> 13) & 0x7u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "SUBS (W, reg-extended)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "SUBS (W, reg-extended)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_extended_rm(cb, x86_rm, option, imm3, true, pc, "SUBS (W, reg-extended)");
        x86_sub_rr32(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SUBS (W, reg-extended)");
        }
        return;
    }

    /* ADDS Xd, Xn, Xm {, <shift> #amount}. CMN alias when Rd==XZR. */
    if ((insn & 0xFF200000u) == 0xAB000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ADDS reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ADDS reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "ADDS");
        x86_add_rr(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ADDS reg");
        }
        return;
    }

    /* ADDS Wd, Wn, Wm {, <shift> #amount}. CMN alias when Rd==WZR. */
    if ((insn & 0xFF200000u) == 0x2B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ADDS (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ADDS (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "ADDS (W, reg)");
        x86_add_rr32(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ADDS (W, reg)");
        }
        return;
    }

    /* SUBS Xd, Xn, Xm {, <shift> #amount}. CMP alias when Rd==XZR. */
    if ((insn & 0xFF200000u) == 0xEB000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "SUBS reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "SUBS reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "SUBS");
        x86_sub_rr(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SUBS reg");
        }
        return;
    }

    /* SUBS Wd, Wn, Wm {, <shift> #amount}. CMP alias when Rd==WZR. */
    if ((insn & 0xFF200000u) == 0x6B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "SUBS (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "SUBS (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "SUBS (W, reg)");
        x86_sub_rr32(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "SUBS (W, reg)");
        }
        return;
    }

    /* ADD Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x8B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADD reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "ADD reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "ADD");
        x86_add_rr(cb, x86_dst, src);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "ADD reg");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ADD Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x0B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "ADD (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "ADD (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "ADD (W, reg)");
        x86_add_rr32(cb, x86_dst, src);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "ADD (W, reg)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SUB Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0xCB000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUB reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "SUB reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "SUB");
        x86_sub_rr(cb, x86_dst, src);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "SUB reg");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* SUB Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x4B000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_sp_read(cb, rn, 13, pc, "SUB (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "SUB (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "SUB (W, reg)");
        x86_sub_rr32(cb, x86_dst, src);
        writeback_guest_xreg_or_sp(cb, rd, x86_dst, pc, "SUB (W, reg)");
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* AND Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x8A000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "AND reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "AND reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "AND");
        x86_and_rr(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "AND reg");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* AND Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x0A000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "AND (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "AND (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_rm = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "AND (W, reg)");
        x86_and_rr32(cb, x86_dst, x86_rm);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "AND (W, reg)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* BIC Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x8A200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "BIC reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "BIC reg");

        emit_preserve_guest_flags_begin(cb);
        x86_rm = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "BIC");
        if (x86_rm != tmp) {
            x86_mov_rr(cb, tmp, x86_rm);
        }
        x86_not_r(cb, tmp);

        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_and_rr(cb, x86_dst, tmp);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "BIC reg");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* BIC Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x0A200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "BIC (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "BIC (W, reg)");

        emit_preserve_guest_flags_begin(cb);
        x86_rm = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "BIC (W, reg)");
        if (x86_rm != tmp) {
            x86_mov_rr32(cb, tmp, x86_rm);
        }
        x86_not_r32(cb, tmp);

        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_and_rr32(cb, x86_dst, tmp);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "BIC (W, reg)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ORR Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0xAA000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ORR reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "ORR reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "ORR");
        x86_or_rr(cb, x86_dst, src);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ORR reg");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ORR Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x2A000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ORR (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "ORR (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "ORR (W, reg)");
        x86_or_rr32(cb, x86_dst, src);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ORR (W, reg)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ORN Xd, Xn, Xm {, <shift> #amount}. MVN alias when Rn==XZR. */
    if ((insn & 0xFF200000u) == 0xAA200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ORN reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ORN reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "ORN");
        if (src != tmp) {
            x86_mov_rr(cb, tmp, src);
        }
        x86_not_r(cb, tmp);
        x86_or_rr(cb, x86_dst, tmp);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ORN reg");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ORN Wd, Wn, Wm {, <shift> #amount}. MVN alias when Rn==WZR. */
    if ((insn & 0xFF200000u) == 0x2A200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ORN (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "ORN (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "ORN (W, reg)");
        if (src != tmp) {
            x86_mov_rr32(cb, tmp, src);
        }
        x86_not_r32(cb, tmp);
        x86_or_rr32(cb, x86_dst, tmp);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "ORN (W, reg)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* EOR Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0xCA000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "EOR reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "EOR reg");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "EOR");
        x86_xor_rr(cb, x86_dst, src);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "EOR reg");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* EOR Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x4A000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rd = map_reg(rd);
        int x86_rn;
        int x86_rm;
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "EOR (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "EOR (W, reg)");
        x86_dst = (rd == 31u) ? 13 : ((x86_rd >= 0) ? x86_rd : 13);

        emit_preserve_guest_flags_begin(cb);
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "EOR (W, reg)");
        x86_xor_rr32(cb, x86_dst, src);
        if (rd != 31u) {
            writeback_guest_xreg(cb, rd, x86_dst, pc, "EOR (W, reg)");
        }
        emit_preserve_guest_flags_end(cb);
        return;
    }

    /* ANDS Xd, Xn, Xm {, <shift> #amount}. TST alias when Rd==XZR. */
    if ((insn & 0xFF200000u) == 0xEA000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rn;
        int x86_rm;
        int x86_rd = map_reg(rd);
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ANDS reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "ANDS reg");

        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "ANDS");

        if (rd == 31u) { /* TST alias */
            x86_test_rr(cb, x86_rn, src);
            return;
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_and_rr(cb, x86_dst, src); /* AND sets flags, matching ANDS behavior for NZCV subset used here */
        writeback_guest_xreg(cb, rd, x86_dst, pc, "ANDS reg");
        return;
    }

    /* ANDS Wd, Wn, Wm {, <shift> #amount}. TST alias when Rd==WZR. */
    if ((insn & 0xFF200000u) == 0x6A000000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rn;
        int x86_rm;
        int x86_rd = map_reg(rd);
        int x86_dst;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "ANDS (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "ANDS (W, reg)");

        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "ANDS (W, reg)");

        if (rd == 31u) { /* TST alias */
            x86_test_rr32(cb, x86_rn, src);
            return;
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_and_rr32(cb, x86_dst, src);
        writeback_guest_xreg(cb, rd, x86_dst, pc, "ANDS (W, reg)");
        return;
    }

    /* BICS Xd, Xn, Xm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0xEA200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rn;
        int x86_rm;
        int x86_rd = map_reg(rd);
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "BICS reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "BICS reg");

        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "BICS");
        if (src != tmp) {
            x86_mov_rr(cb, tmp, src);
        }
        x86_not_r(cb, tmp);

        if (rd == 31u) {
            x86_test_rr(cb, x86_rn, tmp);
            return;
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;
        if (x86_dst != x86_rn) {
            x86_mov_rr(cb, x86_dst, x86_rn);
        }
        x86_and_rr(cb, x86_dst, tmp); /* AND sets flags -> BICS flag behavior subset used here */
        writeback_guest_xreg(cb, rd, x86_dst, pc, "BICS reg");
        return;
    }

    /* BICS Wd, Wn, Wm {, <shift> #amount} */
    if ((insn & 0xFF200000u) == 0x6A200000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rn;
        int x86_rm;
        int x86_rd = map_reg(rd);
        int x86_dst;
        const int tmp = 10; /* r10 scratch */

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "BICS (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "BICS (W, reg)");

        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "BICS (W, reg)");
        if (src != tmp) {
            x86_mov_rr32(cb, tmp, src);
        }
        x86_not_r32(cb, tmp);

        if (rd == 31u) {
            x86_test_rr32(cb, x86_rn, tmp);
            return;
        }

        x86_dst = (x86_rd >= 0) ? x86_rd : 13;
        if (x86_dst != x86_rn) {
            x86_mov_rr32(cb, x86_dst, x86_rn);
        }
        x86_and_rr32(cb, x86_dst, tmp);
        writeback_guest_xreg(cb, rd, x86_dst, pc, "BICS (W, reg)");
        return;
    }

    /* FADD Sn, Sm / FADD Dn, Dm (scalar) */
    if ((insn & 0xFF20FC00u) == 0x1E202800u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        int32_t rd_disp = state_v_qword_offset(rd, 0);
        int32_t rn_disp = state_v_qword_offset(rn, 0);
        int32_t rm_disp = state_v_qword_offset(rm, 0);

        if (is_double) {
            x86_movsd_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movsd_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_addsd_rr(cb, 0, 1);
            x86_movsd_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        } else {
            x86_movss_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movss_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_addss_rr(cb, 0, 1);
            x86_movss_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        }
        return;
    }

    /* FSUB Sn, Sm / FSUB Dn, Dm (scalar) */
    if ((insn & 0xFF20FC00u) == 0x1E203800u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        int32_t rd_disp = state_v_qword_offset(rd, 0);
        int32_t rn_disp = state_v_qword_offset(rn, 0);
        int32_t rm_disp = state_v_qword_offset(rm, 0);

        if (is_double) {
            x86_movsd_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movsd_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_subsd_rr(cb, 0, 1);
            x86_movsd_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        } else {
            x86_movss_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movss_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_subss_rr(cb, 0, 1);
            x86_movss_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        }
        return;
    }

    /* FMUL Sn, Sm / FMUL Dn, Dm (scalar) */
    if ((insn & 0xFF20FC00u) == 0x1E200800u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        int32_t rd_disp = state_v_qword_offset(rd, 0);
        int32_t rn_disp = state_v_qword_offset(rn, 0);
        int32_t rm_disp = state_v_qword_offset(rm, 0);

        if (is_double) {
            x86_movsd_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movsd_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_mulsd_rr(cb, 0, 1);
            x86_movsd_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        } else {
            x86_movss_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movss_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_mulss_rr(cb, 0, 1);
            x86_movss_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        }
        return;
    }

    /* FDIV Sn, Sm / FDIV Dn, Dm (scalar) */
    if ((insn & 0xFF20FC00u) == 0x1E201800u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        int32_t rd_disp = state_v_qword_offset(rd, 0);
        int32_t rn_disp = state_v_qword_offset(rn, 0);
        int32_t rm_disp = state_v_qword_offset(rm, 0);

        if (is_double) {
            x86_movsd_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movsd_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_divsd_rr(cb, 0, 1);
            x86_movsd_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        } else {
            x86_movss_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
            x86_movss_xmm_from_mem_base_disp32(cb, 1, 3, rm_disp);
            x86_divss_rr(cb, 0, 1);
            x86_movss_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
        }
        return;
    }

    /* FMOV Wd, Sn */
    if ((insn & 0xFFFFFC00u) == 0x1E260000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t rn_disp = state_v_qword_offset(rn, 0);

        x86_mov_r32_from_mem_base_disp32(cb, 10, 3, rn_disp);
        writeback_guest_xreg_unless_zr(cb, rd, 10, pc, "FMOV Wd,Sn");
        return;
    }

    /* FMOV Xd, Dn */
    if ((insn & 0xFFFFFC00u) == 0x9E660000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int32_t rn_disp = state_v_qword_offset(rn, 0);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, rn_disp);
        writeback_guest_xreg_unless_zr(cb, rd, 10, pc, "FMOV Xd,Dn");
        return;
    }

    /* FMOV Sn, Wn */
    if ((insn & 0xFFFFFC00u) == 0x1E270000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "FMOV Sn,Wn");
        int32_t rd_disp = state_v_qword_offset(rd, 0);

        x86_mov_mem_base_disp32_from_r32(cb, 3, x86_rn, rd_disp);
        return;
    }

    /* FMOV Dd, Xn */
    if ((insn & 0xFFFFFC00u) == 0x9E670000u) {
        unsigned rd = insn & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "FMOV Dd,Xn");
        int32_t rd_disp = state_v_qword_offset(rd, 0);

        x86_mov_mem_base_disp32_from_r(cb, 3, rd_disp, x86_rn);
        return;
    }

    /* SCVTF {Sd|Dd}, {Wn|Xn} */
    {
        uint32_t op = insn & 0xFF3FFC00u;
        if (op == 0x1E220000u || op == 0x1E620000u || op == 0x9E220000u || op == 0x9E620000u) {
            unsigned rd = insn & 0x1Fu;
            unsigned rn = (insn >> 5) & 0x1Fu;
            bool is_double = (insn & 0x00400000u) != 0u;
            bool is_64 = (insn & 0x80000000u) != 0u;
            int x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "SCVTF");
            int32_t rd_disp = state_v_qword_offset(rd, 0);

            if (is_double) {
                if (is_64) {
                    x86_cvtsi2sd_xmm_from_r64(cb, 0, x86_rn);
                } else {
                    x86_cvtsi2sd_xmm_from_r32(cb, 0, x86_rn);
                }
                x86_movsd_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
            } else {
                if (is_64) {
                    x86_cvtsi2ss_xmm_from_r64(cb, 0, x86_rn);
                } else {
                    x86_cvtsi2ss_xmm_from_r32(cb, 0, x86_rn);
                }
                x86_movss_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
            }
            return;
        }
    }

    /* UCVTF {Sd|Dd}, {Wn|Xn}. */
    {
        uint32_t op = insn & 0xFF3FFC00u;
        if (op == 0x1E230000u || op == 0x1E630000u || op == 0x9E230000u || op == 0x9E630000u) {
            unsigned rd = insn & 0x1Fu;
            unsigned rn = (insn >> 5) & 0x1Fu;
            bool is_double = (insn & 0x00400000u) != 0u;
            bool is_64 = (insn & 0x80000000u) != 0u;
            int x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "UCVTF");
            int32_t rd_disp = state_v_qword_offset(rd, 0);

            if (is_64) {
                /*
                 * Convert full uint64 exactly to floating domain:
                 *   if x < 2^63: cvtsi2s[d](x)
                 *   else: cvtsi2s[d](x>>1) * 2 + (x&1)
                 */
                size_t fast_path_off;
                size_t done_conv_off;

                x86_mov_rr(cb, 10, x86_rn);
                x86_test_rr(cb, 10, 10);
                fast_path_off = x86_jcc_rel32(cb, 0x89); /* JNS */

                /* High unsigned range [2^63, 2^64). */
                x86_mov_rr(cb, 13, 10);
                x86_mov_imm64(cb, 12, 1);
                x86_and_rr(cb, 13, 12);      /* r13 = x & 1 */
                x86_shift_imm(cb, 10, 1, 1); /* r10 = x >> 1 (logical) */
                if (is_double) {
                    x86_cvtsi2sd_xmm_from_r64(cb, 0, 10);
                    x86_addsd_rr(cb, 0, 0);
                    x86_cvtsi2sd_xmm_from_r64(cb, 1, 13);
                    x86_addsd_rr(cb, 0, 1);
                } else {
                    x86_cvtsi2ss_xmm_from_r64(cb, 0, 10);
                    x86_addss_rr(cb, 0, 0);
                    x86_cvtsi2ss_xmm_from_r64(cb, 1, 13);
                    x86_addss_rr(cb, 0, 1);
                }
                done_conv_off = x86_jmp_rel32(cb);

                /* Low unsigned range [0, 2^63). */
                patch_rel32_at(cb->data, fast_path_off, cb->len);
                if (is_double) {
                    x86_cvtsi2sd_xmm_from_r64(cb, 0, x86_rn);
                } else {
                    x86_cvtsi2ss_xmm_from_r64(cb, 0, x86_rn);
                }

                patch_rel32_at(cb->data, done_conv_off, cb->len);
            } else {
                /* Zero-extend Wn then use 64-bit signed conversion path. */
                x86_mov_rr32(cb, 10, x86_rn);
                if (is_double) {
                    x86_cvtsi2sd_xmm_from_r64(cb, 0, 10);
                } else {
                    x86_cvtsi2ss_xmm_from_r64(cb, 0, 10);
                }
            }

            if (is_double) {
                x86_movsd_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
            } else {
                x86_movss_mem_base_disp32_from_xmm(cb, 3, 0, rd_disp);
            }
            return;
        }
    }

    /* FCVTZS {Wd|Xd}, {Sn|Dn} */
    {
        uint32_t op = insn & 0xFF3FFC00u;
        if (op == 0x1E380000u || op == 0x1E780000u || op == 0x9E380000u || op == 0x9E780000u) {
            unsigned rd = insn & 0x1Fu;
            unsigned rn = (insn >> 5) & 0x1Fu;
            bool is_double = (insn & 0x00400000u) != 0u;
            bool is_64 = (insn & 0x80000000u) != 0u;
            int32_t rn_disp = state_v_qword_offset(rn, 0);

            if (is_double) {
                x86_movsd_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
                if (is_64) {
                    x86_cvttsd2si_r64_from_xmm(cb, 10, 0);
                } else {
                    x86_cvttsd2si_r32_from_xmm(cb, 10, 0);
                }
            } else {
                x86_movss_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
                if (is_64) {
                    x86_cvttss2si_r64_from_xmm(cb, 10, 0);
                } else {
                    x86_cvttss2si_r32_from_xmm(cb, 10, 0);
                }
            }
            writeback_guest_xreg_unless_zr(cb, rd, 10, pc, "FCVTZS");
            return;
        }
    }

    /* FCVTZU {Wd|Xd}, {Sn|Dn}. */
    {
        uint32_t op = insn & 0xFF3FFC00u;
        if (op == 0x1E390000u || op == 0x1E790000u || op == 0x9E390000u || op == 0x9E790000u) {
            unsigned rd = insn & 0x1Fu;
            unsigned rn = (insn >> 5) & 0x1Fu;
            bool is_double = (insn & 0x00400000u) != 0u;
            bool is_64 = (insn & 0x80000000u) != 0u;
            int32_t rn_disp = state_v_qword_offset(rn, 0);

            /*
             * Handle unsigned high range explicitly:
             * - 64-bit: threshold 2^63
             * - 32-bit: threshold 2^31
             *
             * Below threshold we can use signed CVTT directly.
             * Above/equal threshold: subtract threshold, CVTT, then add threshold back.
             */
            size_t high_path_off;
            size_t done_conv_off;
            uint64_t half_threshold = is_64 ? (1ull << 62) : (1ull << 30);

            if (is_double) {
                x86_movsd_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
                x86_mov_imm64(cb, 13, half_threshold);
                x86_cvtsi2sd_xmm_from_r64(cb, 1, 13);
                x86_addsd_rr(cb, 1, 1); /* xmm1 = threshold */
                x86_ucomisd_rr(cb, 0, 1);
            } else {
                x86_movss_xmm_from_mem_base_disp32(cb, 0, 3, rn_disp);
                x86_mov_imm64(cb, 13, half_threshold);
                x86_cvtsi2ss_xmm_from_r64(cb, 1, 13);
                x86_addss_rr(cb, 1, 1); /* xmm1 = threshold */
                x86_ucomiss_rr(cb, 0, 1);
            }
            high_path_off = x86_jcc_rel32(cb, 0x83); /* JAE */

            /* Fast path: value < threshold */
            if (is_double) {
                if (is_64) {
                    x86_cvttsd2si_r64_from_xmm(cb, 10, 0);
                } else {
                    x86_cvttsd2si_r32_from_xmm(cb, 10, 0);
                }
            } else {
                if (is_64) {
                    x86_cvttss2si_r64_from_xmm(cb, 10, 0);
                } else {
                    x86_cvttss2si_r32_from_xmm(cb, 10, 0);
                }
            }
            done_conv_off = x86_jmp_rel32(cb);

            /* High path: value >= threshold */
            patch_rel32_at(cb->data, high_path_off, cb->len);
            if (is_double) {
                x86_subsd_rr(cb, 0, 1);
                if (is_64) {
                    x86_cvttsd2si_r64_from_xmm(cb, 10, 0);
                } else {
                    x86_cvttsd2si_r32_from_xmm(cb, 10, 0);
                }
            } else {
                x86_subss_rr(cb, 0, 1);
                if (is_64) {
                    x86_cvttss2si_r64_from_xmm(cb, 10, 0);
                } else {
                    x86_cvttss2si_r32_from_xmm(cb, 10, 0);
                }
            }
            if (is_64) {
                x86_mov_imm64(cb, 13, (1ull << 63));
                x86_add_rr(cb, 10, 13);
            } else {
                x86_add_imm32_32(cb, 10, 0x80000000u);
            }

            patch_rel32_at(cb->data, done_conv_off, cb->len);
            writeback_guest_xreg_unless_zr(cb, rd, 10, pc, "FCVTZU");
            return;
        }
    }

    /* FCMP Sn, Sm / FCMP Dn, Dm */
    if ((insn & 0xFF20FC1Fu) == 0x1E202000u) {
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        emit_fp_compare_set_nzcv(cb, rn, rm, is_double);
        return;
    }

    /* FCMP Sn, #0.0 / FCMP Dn, #0.0 */
    if ((insn & 0xFF20FC1Fu) == 0x1E202008u) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        emit_fp_compare_imm0_set_nzcv(cb, rn, is_double);
        return;
    }

    /*
     * FCMPE Sn, Sm / FCMPE Dn, Dm.
     * PoC note: signaling-vs-quiet exception behavior is currently treated
     * the same as FCMP for NZCV purposes.
     */
    if ((insn & 0xFF20FC1Fu) == 0x1E202010u) {
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        emit_fp_compare_set_nzcv(cb, rn, rm, is_double);
        return;
    }

    /* FCMPE Sn, #0.0 / FCMPE Dn, #0.0 */
    if ((insn & 0xFF20FC1Fu) == 0x1E202018u) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        bool is_double = (insn & 0x00400000u) != 0u;
        emit_fp_compare_imm0_set_nzcv(cb, rn, is_double);
        return;
    }

    /* FCCMP Sn, Sm, #nzcv, <cond> / FCCMP Dn, Dm, #nzcv, <cond> */
    if ((insn & 0xFFA00C10u) == 0x1E200400u) {
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned nzcv_imm4 = insn & 0xFu;
        bool is_double = (insn & 0x00400000u) != 0u;

        if (cond == 0xFu) { /* NV: condition false => fallback NZCV */
            emit_set_nzcv_imm4(cb, nzcv_imm4);
            return;
        }
        if (cond != 0xEu) { /* not AL */
            int cc = arm_cond_to_x86_cc(cond);
            size_t do_cmp_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0Fu)));
            size_t done_off;

            emit_set_nzcv_imm4(cb, nzcv_imm4);
            done_off = x86_jmp_rel32(cb);

            patch_rel32_at(cb->data, do_cmp_off, cb->len);
            emit_fp_compare_set_nzcv(cb, rn, rm, is_double);
            patch_rel32_at(cb->data, done_off, cb->len);
            return;
        }

        emit_fp_compare_set_nzcv(cb, rn, rm, is_double);
        return;
    }

    /*
     * FCCMPE Sn, Sm, #nzcv, <cond> / FCCMPE Dn, Dm, #nzcv, <cond>.
     * PoC note: signaling-vs-quiet exception behavior is currently treated
     * the same as FCCMP (NZCV result still follows ordered/unordered compare).
     */
    if ((insn & 0xFFA00C10u) == 0x1E200410u) {
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned nzcv_imm4 = insn & 0xFu;
        bool is_double = (insn & 0x00400000u) != 0u;

        if (cond == 0xFu) { /* NV: condition false => fallback NZCV */
            emit_set_nzcv_imm4(cb, nzcv_imm4);
            return;
        }
        if (cond != 0xEu) { /* not AL */
            int cc = arm_cond_to_x86_cc(cond);
            size_t do_cmp_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0Fu)));
            size_t done_off;

            emit_set_nzcv_imm4(cb, nzcv_imm4);
            done_off = x86_jmp_rel32(cb);

            patch_rel32_at(cb->data, do_cmp_off, cb->len);
            emit_fp_compare_set_nzcv(cb, rn, rm, is_double);
            patch_rel32_at(cb->data, done_off, cb->len);
            return;
        }

        emit_fp_compare_set_nzcv(cb, rn, rm, is_double);
        return;
    }

    /* CCMP {Wn, Wm}/{Xn, Xm}, #nzcv, <cond> */
    if ((insn & 0x7FE00C10u) == 0x7A400000u) {
        unsigned sf = (insn >> 31) & 1u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned nzcv_imm4 = insn & 0xFu;
        int x86_rn;
        int x86_rm;

        if (cond == 0xFu) { /* NV: condition false => fallback NZCV */
            emit_set_nzcv_imm4(cb, nzcv_imm4);
            return;
        }

        if (cond != 0xEu) { /* not AL */
            int cc = arm_cond_to_x86_cc(cond);
            size_t do_cmp_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0Fu)));
            size_t done_off;

            emit_set_nzcv_imm4(cb, nzcv_imm4);
            done_off = x86_jmp_rel32(cb);

            patch_rel32_at(cb->data, do_cmp_off, cb->len);
            x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMP reg");
            x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CCMP reg");
            if (sf != 0u) {
                x86_cmp_rr(cb, x86_rn, x86_rm);
            } else {
                x86_cmp_rr32(cb, x86_rn, x86_rm);
            }
            patch_rel32_at(cb->data, done_off, cb->len);
            return;
        }

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMP reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CCMP reg");
        if (sf != 0u) {
            x86_cmp_rr(cb, x86_rn, x86_rm);
        } else {
            x86_cmp_rr32(cb, x86_rn, x86_rm);
        }
        return;
    }

    /* CCMP {Wn, #imm5}/{Xn, #imm5}, #nzcv, <cond> */
    if ((insn & 0x7FE00C10u) == 0x7A400800u) {
        unsigned sf = (insn >> 31) & 1u;
        unsigned imm5 = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned nzcv_imm4 = insn & 0xFu;
        int x86_rn;

        if (cond == 0xFu) { /* NV: condition false => fallback NZCV */
            emit_set_nzcv_imm4(cb, nzcv_imm4);
            return;
        }

        if (cond != 0xEu) { /* not AL */
            int cc = arm_cond_to_x86_cc(cond);
            size_t do_cmp_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0Fu)));
            size_t done_off;

            emit_set_nzcv_imm4(cb, nzcv_imm4);
            done_off = x86_jmp_rel32(cb);

            patch_rel32_at(cb->data, do_cmp_off, cb->len);
            x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMP imm");
            if (sf != 0u) {
                x86_cmp_imm32(cb, x86_rn, imm5);
            } else {
                x86_cmp_imm32_32(cb, x86_rn, imm5);
            }
            patch_rel32_at(cb->data, done_off, cb->len);
            return;
        }

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMP imm");
        if (sf != 0u) {
            x86_cmp_imm32(cb, x86_rn, imm5);
        } else {
            x86_cmp_imm32_32(cb, x86_rn, imm5);
        }
        return;
    }

    /* CCMN {Wn, Wm}/{Xn, Xm}, #nzcv, <cond> */
    if ((insn & 0x7FE00C10u) == 0x3A400000u) {
        unsigned sf = (insn >> 31) & 1u;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned nzcv_imm4 = insn & 0xFu;
        int x86_rn;
        int x86_rm;

        if (cond == 0xFu) { /* NV: condition false => fallback NZCV */
            emit_set_nzcv_imm4(cb, nzcv_imm4);
            return;
        }

        if (cond != 0xEu) { /* not AL */
            int cc = arm_cond_to_x86_cc(cond);
            size_t do_cmn_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0Fu)));
            size_t done_off;

            emit_set_nzcv_imm4(cb, nzcv_imm4);
            done_off = x86_jmp_rel32(cb);

            patch_rel32_at(cb->data, do_cmn_off, cb->len);
            x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMN reg");
            x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "CCMN reg");
            if (sf != 0u) {
                x86_mov_rr(cb, 10, x86_rn);
                x86_add_rr(cb, 10, x86_rm);
            } else {
                x86_mov_rr32(cb, 10, x86_rn);
                x86_add_rr32(cb, 10, x86_rm);
            }
            patch_rel32_at(cb->data, done_off, cb->len);
            return;
        }

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMN reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 12, pc, "CCMN reg");
        if (sf != 0u) {
            x86_mov_rr(cb, 10, x86_rn);
            x86_add_rr(cb, 10, x86_rm);
        } else {
            x86_mov_rr32(cb, 10, x86_rn);
            x86_add_rr32(cb, 10, x86_rm);
        }
        return;
    }

    /* CCMN {Wn, #imm5}/{Xn, #imm5}, #nzcv, <cond> */
    if ((insn & 0x7FE00C10u) == 0x3A400800u) {
        unsigned sf = (insn >> 31) & 1u;
        unsigned imm5 = (insn >> 16) & 0x1Fu;
        unsigned cond = (insn >> 12) & 0xFu;
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned nzcv_imm4 = insn & 0xFu;
        int x86_rn;

        if (cond == 0xFu) { /* NV: condition false => fallback NZCV */
            emit_set_nzcv_imm4(cb, nzcv_imm4);
            return;
        }

        if (cond != 0xEu) { /* not AL */
            int cc = arm_cond_to_x86_cc(cond);
            size_t do_cmn_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0Fu)));
            size_t done_off;

            emit_set_nzcv_imm4(cb, nzcv_imm4);
            done_off = x86_jmp_rel32(cb);

            patch_rel32_at(cb->data, do_cmn_off, cb->len);
            x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMN imm");
            if (sf != 0u) {
                x86_mov_rr(cb, 10, x86_rn);
                x86_add_imm32(cb, 10, imm5);
            } else {
                x86_mov_rr32(cb, 10, x86_rn);
                x86_add_imm32_32(cb, 10, imm5);
            }
            patch_rel32_at(cb->data, done_off, cb->len);
            return;
        }

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CCMN imm");
        if (sf != 0u) {
            x86_mov_rr(cb, 10, x86_rn);
            x86_add_imm32(cb, 10, imm5);
        } else {
            x86_mov_rr32(cb, 10, x86_rn);
            x86_add_imm32_32(cb, 10, imm5);
        }
        return;
    }

    /* CMP Xn, Xm (alias SUBS XZR, Xn, Xm) */
    if ((insn & 0xFF20001Fu) == 0xEB00001Fu) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rn;
        int x86_rm;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CMP reg");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CMP reg");

        int src = materialize_shifted_rm(cb, x86_rm, shift, imm6, pc, "CMP");
        x86_cmp_rr(cb, x86_rn, src);
        return;
    }

    /* CMP Wn, Wm (alias SUBS WZR, Wn, Wm) */
    if ((insn & 0xFF20001Fu) == 0x6B00001Fu) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        unsigned imm6 = (insn >> 10) & 0x3Fu;
        unsigned rm = (insn >> 16) & 0x1Fu;
        unsigned shift = (insn >> 22) & 0x3u;
        int x86_rn;
        int x86_rm;

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 13, pc, "CMP (W, reg)");
        x86_rm = materialize_guest_xreg_or_zr_read(cb, rm, 10, pc, "CMP (W, reg)");

        int src = materialize_shifted_rm32(cb, x86_rm, shift, imm6, pc, "CMP (W, reg)");
        x86_cmp_rr32(cb, x86_rn, src);
        return;
    }

    /* B <label> */
    if ((insn & 0xFC000000u) == 0x14000000u) {
        int32_t imm26 = sign_extend32(insn & 0x03FFFFFFu, 26);
        int target_pc = (int)pc + imm26;
        size_t imm_off = x86_jmp_rel32(cb);
        pv_push(patches, imm_off, target_pc);
        return;
    }

    /* BL <label> */
    if ((insn & 0xFC000000u) == 0x94000000u) {
        int32_t imm26 = sign_extend32(insn & 0x03FFFFFFu, 26);
        int target_pc = (int)pc + imm26;
        emit_preserve_guest_flags_begin(cb);

        /* Push current LR (x30) onto a tiny software return stack. */
        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, lr_sp_bytes)); /* r10 = sp(bytes) */
        x86_cmp_imm32(cb, 10, (uint32_t)(LR_STACK_MAX_BYTES - 1));
        size_t overflow_off = x86_ja_rel32(cb);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_x_offset(30));                        /* r13 = old LR */
        x86_mov_mem_base_index_disp32_from_r(cb, 3, 10, 13, (int32_t)offsetof(CPUState, lr_stack));
        x86_add_imm32(cb, 10, 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, lr_sp_bytes), 10);

        /* LR = return PC (pc + 1), in bytes. */
        x86_mov_imm64(cb, 13, (uint64_t)((pc + 1u) * 4u));
        x86_mov_mem_base_disp32_from_r(cb, 3, state_x_offset(30), 13);

        emit_preserve_guest_flags_end(cb);
        size_t imm_off = x86_jmp_rel32(cb);
        pv_push(patches, imm_off, target_pc);

        size_t overflow_path_off = cb->len;
        patch_rel32_at(cb->data, overflow_off, overflow_path_off);
        emit_preserve_guest_flags_end(cb);
        emit_set_state_pc_bytes(cb, (uint64_t)(n_insn * 4u));
        x86_mov_imm64(cb, 0, UINT64_MAX);
        emit_save_rflags(cb);
        offv_push(dispatch_patches, x86_jmp_rel32(cb));
        return;
    }

    /* BR Xn */
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rn;
        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "BR");
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, pc), x86_rn);
        emit_save_rflags(cb);
        offv_push(dispatch_patches, x86_jmp_rel32(cb));
        return;
    }

    /* BLR Xn */
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rn;

        emit_preserve_guest_flags_begin(cb);

        /* Push current LR (x30) onto a tiny software return stack. */
        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, lr_sp_bytes)); /* r10 = sp(bytes) */
        x86_cmp_imm32(cb, 10, (uint32_t)(LR_STACK_MAX_BYTES - 1));
        size_t overflow_off = x86_ja_rel32(cb);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, state_x_offset(30));                        /* r13 = old LR */
        x86_mov_mem_base_index_disp32_from_r(cb, 3, 10, 13, (int32_t)offsetof(CPUState, lr_stack));
        x86_add_imm32(cb, 10, 8);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, lr_sp_bytes), 10);

        /* LR = return PC (pc + 1), in bytes. */
        x86_mov_imm64(cb, 13, (uint64_t)((pc + 1u) * 4u));
        x86_mov_mem_base_disp32_from_r(cb, 3, state_x_offset(30), 13);

        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "BLR");
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, pc), x86_rn);

        emit_preserve_guest_flags_end(cb);
        emit_save_rflags(cb);
        offv_push(dispatch_patches, x86_jmp_rel32(cb));

        size_t overflow_path_off = cb->len;
        patch_rel32_at(cb->data, overflow_off, overflow_path_off);
        emit_preserve_guest_flags_end(cb);
        emit_set_state_pc_bytes(cb, (uint64_t)(n_insn * 4u));
        x86_mov_imm64(cb, 0, UINT64_MAX);
        emit_save_rflags(cb);
        offv_push(dispatch_patches, x86_jmp_rel32(cb));
        return;
    }

    /* B.cond <label> */
    if ((insn & 0xFF000010u) == 0x54000000u) {
        int32_t imm19 = sign_extend32((insn >> 5) & 0x7FFFFu, 19);
        int target_pc = (int)pc + imm19;
        unsigned cond = insn & 0xFu;
        int cc = arm_cond_to_x86_cc(cond);

        if (cond == 0xE) { /* AL */
            size_t off = x86_jmp_rel32(cb);
            pv_push(patches, off, target_pc);
            return;
        }
        if (cc < 0) {
            fprintf(stderr, "unsupported B.cond condition 0x%x at pc=%zu\n", cond, pc);
            exit(1);
        }

        size_t taken_off = x86_jcc_rel32(cb, (uint8_t)(0x80 | (cc & 0x0F)));
        size_t fallthrough_off = x86_jmp_rel32(cb);
        pv_push(patches, taken_off, target_pc);
        pv_push(patches, fallthrough_off, (int)(pc + 1u));
        return;
    }

    /* CBZ/CBNZ {Wt|Xt}, <label> */
    if ((insn & 0x7E000000u) == 0x34000000u) {
        unsigned sf = (insn >> 31) & 1u;
        unsigned op = (insn >> 24) & 1u; /* 0=CBZ, 1=CBNZ */
        unsigned rt = insn & 0x1Fu;
        int32_t imm19 = sign_extend32((insn >> 5) & 0x7FFFFu, 19);
        int target_pc = (int)pc + imm19;
        int x86_rt;

        x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 10, pc, "CBZ/CBNZ");

        emit_preserve_guest_flags_begin(cb);
        if (sf) {
            x86_test_rr(cb, x86_rt, x86_rt);
        } else {
            x86_test_rr32(cb, x86_rt, x86_rt);
        }
        size_t taken_test_off = (op == 0) ? x86_jz_rel32(cb) : x86_jnz_rel32(cb);

        emit_preserve_guest_flags_end(cb);
        size_t fallthrough_off = x86_jmp_rel32(cb);

        size_t taken_path_off = cb->len;
        patch_rel32_at(cb->data, taken_test_off, taken_path_off);
        emit_preserve_guest_flags_end(cb);
        size_t taken_off = x86_jmp_rel32(cb);

        pv_push(patches, taken_off, target_pc);
        pv_push(patches, fallthrough_off, (int)(pc + 1u));
        return;
    }

    /* TBZ/TBNZ {Wn|Xn}, #bit, <label> */
    if ((insn & 0x7E000000u) == 0x36000000u) {
        unsigned op = (insn >> 24) & 1u; /* 0=TBZ, 1=TBNZ */
        unsigned b5 = (insn >> 31) & 1u;
        unsigned b40 = (insn >> 19) & 0x1Fu;
        unsigned bit_pos = (b5 << 5) | b40;
        unsigned rt = insn & 0x1Fu;
        int32_t imm14 = sign_extend32((insn >> 5) & 0x3FFFu, 14);
        int target_pc = (int)pc + imm14;
        int x86_rt;

        x86_rt = materialize_guest_xreg_or_zr_read(cb, rt, 10, pc, "TBZ/TBNZ");

        emit_preserve_guest_flags_begin(cb);
        x86_bt_imm8(cb, x86_rt, (uint8_t)bit_pos);
        size_t taken_test_off = (op == 0) ? x86_jnc_rel32(cb) : x86_jc_rel32(cb);

        emit_preserve_guest_flags_end(cb);
        size_t fallthrough_off = x86_jmp_rel32(cb);

        size_t taken_path_off = cb->len;
        patch_rel32_at(cb->data, taken_test_off, taken_path_off);
        emit_preserve_guest_flags_end(cb);
        size_t taken_off = x86_jmp_rel32(cb);

        pv_push(patches, taken_off, target_pc);
        pv_push(patches, fallthrough_off, (int)(pc + 1u));
        return;
    }

    /* RET Xn */
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) {
        unsigned rn = (insn >> 5) & 0x1Fu;
        int x86_rn;

        emit_preserve_guest_flags_begin(cb);
        x86_rn = materialize_guest_xreg_or_zr_read(cb, rn, 10, pc, "RET");
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, pc), x86_rn);

        /*
         * For RET X30, model nested call/return by restoring caller LR after
         * capturing the jump target from current X30.
         */
        if (rn == 30u) {
            x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, lr_sp_bytes));
            x86_cmp_imm32(cb, 10, (uint32_t)LR_STACK_MAX_BYTES);
            size_t bad_stack_off = x86_ja_rel32(cb);
            x86_test_rr(cb, 10, 10);
            size_t no_pop_off = x86_jz_rel32(cb);

            x86_sub_imm32(cb, 10, 8);
            x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, lr_sp_bytes), 10);
            x86_mov_r_from_mem_base_index_disp32(cb, 13, 3, 10, (int32_t)offsetof(CPUState, lr_stack));
            x86_mov_mem_base_disp32_from_r(cb, 3, state_x_offset(30), 13);

            patch_rel32_at(cb->data, no_pop_off, cb->len);

            size_t continue_off = x86_jmp_rel32(cb);
            size_t bad_stack_path_off = cb->len;
            patch_rel32_at(cb->data, bad_stack_off, bad_stack_path_off);
            emit_preserve_guest_flags_end(cb);
            emit_set_state_pc_bytes(cb, (uint64_t)(n_insn * 4u));
            x86_mov_imm64(cb, 0, UINT64_MAX);
            emit_save_rflags(cb);
            offv_push(dispatch_patches, x86_jmp_rel32(cb));
            patch_rel32_at(cb->data, continue_off, cb->len);
        }

        emit_preserve_guest_flags_end(cb);
        emit_save_rflags(cb);

        /* Fast-path chaining for RET: tiny inline cache (pc -> host target). */
        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, pc)); /* r10 = next pc bytes */
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, (int32_t)offsetof(CPUState, ret_ic_key));
        x86_cmp_rr(cb, 10, 13);
        size_t to_ic_miss_key = x86_jnz_rel32(cb);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, (int32_t)offsetof(CPUState, ret_ic_target));
        x86_test_rr(cb, 13, 13);
        size_t to_ic_miss_target = x86_jz_rel32(cb);
        x86_mov_r_from_mem_base_disp32(cb, 12, 3, (int32_t)offsetof(CPUState, ret_ic_version));
        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, dispatch_version));
        x86_cmp_rr(cb, 12, 10);
        size_t to_ic_miss_version = x86_jnz_rel32(cb);

        emit_restore_rflags(cb);
        x86_jmp_r(cb, 13);

        /* IC miss: resolve next block directly via entry table and fill cache. */
        size_t ic_miss_off = cb->len;
        patch_rel32_at(cb->data, to_ic_miss_key, ic_miss_off);
        patch_rel32_at(cb->data, to_ic_miss_target, ic_miss_off);
        patch_rel32_at(cb->data, to_ic_miss_version, ic_miss_off);

        x86_mov_r_from_mem_base_disp32(cb, 10, 3, (int32_t)offsetof(CPUState, pc));
        x86_shift_imm(cb, 10, 1, 2); /* pc bytes -> instruction index */
        x86_cmp_imm32(cb, 10, (uint32_t)n_insn);
        size_t to_dispatch_oob = x86_ja_rel32(cb);

        x86_shift_imm(cb, 10, 0, 3); /* entry index -> byte offset */
        x86_mov_rr(cb, 13, 10); /* save entry byte offset */
        x86_mov_imm64(cb, 12, (uint64_t)(uintptr_t)entry_targets);
        x86_mov_r_from_mem_base_index_disp32(cb, 10, 12, 10, 0);
        x86_test_rr(cb, 10, 10);
        size_t to_dispatch_miss = x86_jz_rel32(cb);
        x86_mov_imm64(cb, 12, (uint64_t)(uintptr_t)entry_versions);
        x86_mov_r_from_mem_base_index_disp32(cb, 12, 12, 13, 0);
        x86_mov_r_from_mem_base_disp32(cb, 13, 3, (int32_t)offsetof(CPUState, dispatch_version));
        x86_cmp_rr(cb, 12, 13);
        size_t to_dispatch_version_miss = x86_jnz_rel32(cb);

        x86_mov_r_from_mem_base_disp32(cb, 13, 3, (int32_t)offsetof(CPUState, pc));
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, ret_ic_key), 13);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, ret_ic_target), 10);
        x86_mov_mem_base_disp32_from_r(cb, 3, (int32_t)offsetof(CPUState, ret_ic_version), 12);
        x86_mov_rr(cb, 13, 10); /* preserve target across emit_restore_rflags() */
        emit_restore_rflags(cb);
        x86_jmp_r(cb, 13);

        size_t fallback_off = cb->len;
        patch_rel32_at(cb->data, to_dispatch_oob, fallback_off);
        patch_rel32_at(cb->data, to_dispatch_miss, fallback_off);
        patch_rel32_at(cb->data, to_dispatch_version_miss, fallback_off);
        offv_push(dispatch_patches, x86_jmp_rel32(cb));
        return;
    }

    unsupportedv_push(unsupported_patches, x86_jmp_rel32(cb), (uint64_t)(pc * 4u), insn);
    return;
}
