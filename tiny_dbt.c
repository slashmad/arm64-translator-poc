#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tiny_dbt_runtime.h"

typedef struct {
    uint64_t addr;
    size_t len;
    const char *out_path;
} MemReadSpec;

typedef struct {
    uint64_t addr;
    uint8_t *bytes;
    size_t len;
} MemWriteSpec;

typedef struct {
    char *name;
    uint64_t value;
} ElfImportStubSpec;

typedef struct {
    char *name;
    uint8_t callback_id;
} ElfImportCallbackSpec;

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

typedef struct {
    uint64_t plt_addr;
    uint32_t plt_slot_size;
    const char *name;
} ElfPltImport;

typedef struct {
    bool show_help;
    const char *code_file;
    const char *elf_file;
    const char *elf_symbol;
    size_t elf_size_override;
    bool has_elf_size_override;
    ElfImportStubSpec *elf_import_stubs;
    size_t n_elf_import_stubs;
    size_t elf_import_stubs_cap;
    ElfImportCallbackSpec *elf_import_callbacks;
    size_t n_elf_import_callbacks;
    size_t elf_import_callbacks_cap;
    const char *elf_import_trace_path;
    TinyDbtCpuState initial_state;
    bool has_initial_state;
    bool trace_state;
    MemReadSpec *mem_reads;
    size_t n_mem_reads;
    size_t mem_reads_cap;
    MemWriteSpec *mem_writes;
    size_t n_mem_writes;
    size_t mem_writes_cap;
    bool invalidate_dispatch;
    bool invalidate_all_slots;
    const char *invalidate_pc_indexes;
    bool debug_exit;
    size_t max_retries;
    bool has_max_retries;
    const char *unsupported_log_path;
    int first_opcode_arg;
} CliOptions;

static bool env_flag_enabled(const char *name) {
    const char *v = getenv(name);
    return v && v[0] != '\0' && strcmp(v, "0") != 0;
}

static bool parse_max_retries(const char *s, size_t *out) {
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v == 0 || v > 4096) {
        return false;
    }
    *out = (size_t)v;
    return true;
}

static bool parse_u64_arg(const char *s, uint64_t *out) {
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

static bool parse_size_arg(const char *s, size_t *out) {
    uint64_t v = 0;
    if (!parse_u64_arg(s, &v) || v == 0 || v > SIZE_MAX) {
        return false;
    }
    *out = (size_t)v;
    return true;
}

static bool parse_elf_import_stub_spec(const char *s, ElfImportStubSpec *out) {
    const char *eq = strchr(s, '=');
    if (!eq || eq == s || eq[1] == '\0') {
        return false;
    }

    size_t name_len = (size_t)(eq - s);
    char *name = malloc(name_len + 1u);
    if (!name) {
        return false;
    }
    memcpy(name, s, name_len);
    name[name_len] = '\0';

    uint64_t value = 0;
    if (!parse_u64_arg(eq + 1, &value)) {
        free(name);
        return false;
    }

    out->name = name;
    out->value = value;
    return true;
}

static bool parse_elf_import_callback_kind(const char *kind, uint8_t *out_callback_id) {
    if (!kind || !out_callback_id) {
        return false;
    }

    if (strcmp(kind, "add_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_ADD_X0_X1;
        return true;
    }
    if (strcmp(kind, "sub_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_SUB_X0_X1;
        return true;
    }
    if (strcmp(kind, "ret_sp") == 0) {
        *out_callback_id = IMPORT_CB_RET_SP;
        return true;
    }
    if (strcmp(kind, "nonnull_x0") == 0) {
        *out_callback_id = IMPORT_CB_NONNULL_X0;
        return true;
    }
    if (strcmp(kind, "guest_alloc_x0") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_ALLOC_X0;
        return true;
    }
    if (strcmp(kind, "guest_free_x0") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_FREE_X0;
        return true;
    }
    if (strcmp(kind, "guest_calloc_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_CALLOC_X0_X1;
        return true;
    }
    if (strcmp(kind, "guest_realloc_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_REALLOC_X0_X1;
        return true;
    }
    if (strcmp(kind, "guest_memcpy_x0_x1_x2") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_MEMCPY_X0_X1_X2;
        return true;
    }
    if (strcmp(kind, "guest_memset_x0_x1_x2") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_MEMSET_X0_X1_X2;
        return true;
    }
    if (strcmp(kind, "guest_memcmp_x0_x1_x2") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_MEMCMP_X0_X1_X2;
        return true;
    }
    if (strcmp(kind, "guest_memmove_x0_x1_x2") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_MEMMOVE_X0_X1_X2;
        return true;
    }
    if (strcmp(kind, "guest_strnlen_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRNLEN_X0_X1;
        return true;
    }
    if (strcmp(kind, "guest_strlen_x0") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRLEN_X0;
        return true;
    }
    if (strcmp(kind, "guest_strcmp_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRCMP_X0_X1;
        return true;
    }
    if (strcmp(kind, "guest_strncmp_x0_x1_x2") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRNCMP_X0_X1_X2;
        return true;
    }
    if (strcmp(kind, "guest_strcpy_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRCPY_X0_X1;
        return true;
    }
    if (strcmp(kind, "guest_strncpy_x0_x1_x2") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRNCPY_X0_X1_X2;
        return true;
    }
    if (strcmp(kind, "guest_strchr_x0_x1") == 0) {
        *out_callback_id = IMPORT_CB_GUEST_STRCHR_X0_X1;
        return true;
    }
    if (strncmp(kind, "ret_x", 5) == 0 && kind[5] >= '0' && kind[5] <= '7' && kind[6] == '\0') {
        *out_callback_id = (uint8_t)(IMPORT_CB_RET_X0 + (uint8_t)(kind[5] - '0'));
        return true;
    }
    return false;
}

static const char *import_callback_kind_name(uint8_t callback_id) {
    switch (callback_id) {
        case IMPORT_CB_RET_X0:
            return "ret_x0";
        case IMPORT_CB_RET_X1:
            return "ret_x1";
        case IMPORT_CB_RET_X2:
            return "ret_x2";
        case IMPORT_CB_RET_X3:
            return "ret_x3";
        case IMPORT_CB_RET_X4:
            return "ret_x4";
        case IMPORT_CB_RET_X5:
            return "ret_x5";
        case IMPORT_CB_RET_X6:
            return "ret_x6";
        case IMPORT_CB_RET_X7:
            return "ret_x7";
        case IMPORT_CB_ADD_X0_X1:
            return "add_x0_x1";
        case IMPORT_CB_SUB_X0_X1:
            return "sub_x0_x1";
        case IMPORT_CB_RET_SP:
            return "ret_sp";
        case IMPORT_CB_NONNULL_X0:
            return "nonnull_x0";
        case IMPORT_CB_GUEST_ALLOC_X0:
            return "guest_alloc_x0";
        case IMPORT_CB_GUEST_FREE_X0:
            return "guest_free_x0";
        case IMPORT_CB_GUEST_CALLOC_X0_X1:
            return "guest_calloc_x0_x1";
        case IMPORT_CB_GUEST_REALLOC_X0_X1:
            return "guest_realloc_x0_x1";
        case IMPORT_CB_GUEST_MEMCPY_X0_X1_X2:
            return "guest_memcpy_x0_x1_x2";
        case IMPORT_CB_GUEST_MEMSET_X0_X1_X2:
            return "guest_memset_x0_x1_x2";
        case IMPORT_CB_GUEST_MEMCMP_X0_X1_X2:
            return "guest_memcmp_x0_x1_x2";
        case IMPORT_CB_GUEST_MEMMOVE_X0_X1_X2:
            return "guest_memmove_x0_x1_x2";
        case IMPORT_CB_GUEST_STRNLEN_X0_X1:
            return "guest_strnlen_x0_x1";
        case IMPORT_CB_GUEST_STRLEN_X0:
            return "guest_strlen_x0";
        case IMPORT_CB_GUEST_STRCMP_X0_X1:
            return "guest_strcmp_x0_x1";
        case IMPORT_CB_GUEST_STRNCMP_X0_X1_X2:
            return "guest_strncmp_x0_x1_x2";
        case IMPORT_CB_GUEST_STRCPY_X0_X1:
            return "guest_strcpy_x0_x1";
        case IMPORT_CB_GUEST_STRNCPY_X0_X1_X2:
            return "guest_strncpy_x0_x1_x2";
        case IMPORT_CB_GUEST_STRCHR_X0_X1:
            return "guest_strchr_x0_x1";
        default:
            return "unknown";
    }
}

static bool parse_elf_import_callback_spec(const char *s, ElfImportCallbackSpec *out) {
    const char *eq = strchr(s, '=');
    uint8_t callback_id = 0;
    if (!eq || eq == s || eq[1] == '\0') {
        return false;
    }

    size_t name_len = (size_t)(eq - s);
    char *name = malloc(name_len + 1u);
    if (!name) {
        return false;
    }
    memcpy(name, s, name_len);
    name[name_len] = '\0';

    if (!parse_elf_import_callback_kind(eq + 1, &callback_id)) {
        free(name);
        return false;
    }

    out->name = name;
    out->callback_id = callback_id;
    return true;
}

static bool grow_array(void **ptr, size_t *cap, size_t elem_size) {
    size_t new_cap = (*cap == 0) ? 4 : (*cap * 2);
    if (new_cap < *cap || new_cap > SIZE_MAX / elem_size) {
        return false;
    }
    void *new_ptr = realloc(*ptr, new_cap * elem_size);
    if (!new_ptr) {
        return false;
    }
    *ptr = new_ptr;
    *cap = new_cap;
    return true;
}

static bool add_mem_read_spec(CliOptions *opts, MemReadSpec spec) {
    if (opts->n_mem_reads == opts->mem_reads_cap) {
        if (!grow_array((void **)&opts->mem_reads, &opts->mem_reads_cap, sizeof(*opts->mem_reads))) {
            return false;
        }
    }
    opts->mem_reads[opts->n_mem_reads++] = spec;
    return true;
}

static bool add_mem_write_spec(CliOptions *opts, MemWriteSpec spec) {
    if (opts->n_mem_writes == opts->mem_writes_cap) {
        if (!grow_array((void **)&opts->mem_writes, &opts->mem_writes_cap, sizeof(*opts->mem_writes))) {
            return false;
        }
    }
    opts->mem_writes[opts->n_mem_writes++] = spec;
    return true;
}

static bool add_elf_import_stub_spec(CliOptions *opts, ElfImportStubSpec spec) {
    if (opts->n_elf_import_stubs == opts->elf_import_stubs_cap) {
        if (!grow_array((void **)&opts->elf_import_stubs, &opts->elf_import_stubs_cap, sizeof(*opts->elf_import_stubs))) {
            return false;
        }
    }
    opts->elf_import_stubs[opts->n_elf_import_stubs++] = spec;
    return true;
}

static bool add_elf_import_callback_spec(CliOptions *opts, ElfImportCallbackSpec spec) {
    if (opts->n_elf_import_callbacks == opts->elf_import_callbacks_cap) {
        if (!grow_array((void **)&opts->elf_import_callbacks, &opts->elf_import_callbacks_cap,
                        sizeof(*opts->elf_import_callbacks))) {
            return false;
        }
    }
    opts->elf_import_callbacks[opts->n_elf_import_callbacks++] = spec;
    return true;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static bool parse_mem_read_spec(const char *s, MemReadSpec *out) {
    const char *sep = strchr(s, ':');
    if (!sep || sep == s || sep[1] == '\0') {
        return false;
    }

    size_t addr_len = (size_t)(sep - s);
    if (addr_len >= 64) {
        return false;
    }
    char addr_buf[64];
    memcpy(addr_buf, s, addr_len);
    addr_buf[addr_len] = '\0';

    uint64_t addr = 0;
    uint64_t len_u64 = 0;
    if (!parse_u64_arg(addr_buf, &addr) || !parse_u64_arg(sep + 1, &len_u64)) {
        return false;
    }
    if (len_u64 == 0 || len_u64 > SIZE_MAX) {
        return false;
    }

    out->addr = addr;
    out->len = (size_t)len_u64;
    out->out_path = NULL;
    return true;
}

static bool parse_mem_write_spec(const char *s, MemWriteSpec *out) {
    const char *sep = strchr(s, ':');
    if (!sep || sep == s || sep[1] == '\0') {
        return false;
    }

    size_t addr_len = (size_t)(sep - s);
    if (addr_len >= 64) {
        return false;
    }
    char addr_buf[64];
    memcpy(addr_buf, s, addr_len);
    addr_buf[addr_len] = '\0';

    uint64_t addr = 0;
    if (!parse_u64_arg(addr_buf, &addr)) {
        return false;
    }

    const char *hex = sep + 1;
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len & 1u) != 0) {
        return false;
    }

    size_t len = hex_len / 2u;
    uint8_t *bytes = malloc(len);
    if (!bytes) {
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            free(bytes);
            return false;
        }
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    out->addr = addr;
    out->bytes = bytes;
    out->len = len;
    return true;
}

static uint8_t *read_binary_file(const char *path, const char *kind, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "failed to open %s '%s': %s\n", kind, path, strerror(errno));
        return NULL;
    }

    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        fclose(f);
        perror("malloc");
        return NULL;
    }

    while (1) {
        if (len == cap) {
            if (cap > SIZE_MAX / 2) {
                fprintf(stderr, "%s too large: %s\n", kind, path);
                free(buf);
                fclose(f);
                return NULL;
            }
            size_t new_cap = cap * 2;
            uint8_t *new_buf = realloc(buf, new_cap);
            if (!new_buf) {
                free(buf);
                fclose(f);
                perror("realloc");
                return NULL;
            }
            buf = new_buf;
            cap = new_cap;
        }

        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) {
            if (ferror(f)) {
                fprintf(stderr, "failed to read %s '%s': %s\n", kind, path, strerror(errno));
                free(buf);
                fclose(f);
                return NULL;
            }
            break;
        }
    }

    fclose(f);
    *out_size = len;
    return buf;
}

static bool range_within(size_t off, size_t len, size_t total) {
    return off <= total && len <= (total - off);
}

static uint32_t load_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static bool find_import_stub_value(const ElfImportStubSpec *specs, size_t n_specs, const char *name, uint64_t *out_value) {
    if (!specs || !name || !out_value) {
        return false;
    }
    for (size_t i = n_specs; i > 0; --i) {
        const ElfImportStubSpec *spec = &specs[i - 1u];
        if (strcmp(spec->name, name) == 0) {
            *out_value = spec->value;
            return true;
        }
    }
    return false;
}

static bool find_import_callback_id(const ElfImportCallbackSpec *specs, size_t n_specs, const char *name,
                                    uint8_t *out_callback_id) {
    if (!specs || !name || !out_callback_id) {
        return false;
    }
    for (size_t i = n_specs; i > 0; --i) {
        const ElfImportCallbackSpec *spec = &specs[i - 1u];
        if (strcmp(spec->name, name) == 0) {
            *out_callback_id = spec->callback_id;
            return true;
        }
    }
    return false;
}

static const ElfPltImport *find_plt_import_for_target(const ElfPltImport *imports, size_t n_imports, uint64_t target_vaddr) {
    if (!imports) {
        return NULL;
    }
    for (size_t i = 0; i < n_imports; ++i) {
        uint64_t start = imports[i].plt_addr;
        uint64_t end = start + (uint64_t)imports[i].plt_slot_size;
        if (end < start) {
            continue;
        }
        if (target_vaddr >= start && target_vaddr < end) {
            return &imports[i];
        }
    }
    return NULL;
}

static bool add_plt_import_entry(ElfPltImport **io_imports, size_t *io_n, size_t *io_cap, ElfPltImport entry) {
    if (*io_n == *io_cap) {
        if (!grow_array((void **)io_imports, io_cap, sizeof(**io_imports))) {
            return false;
        }
    }
    (*io_imports)[(*io_n)++] = entry;
    return true;
}

static bool collect_elf_plt_imports_sections(const uint8_t *file, size_t file_size, const Elf64_Ehdr *eh,
                                             const Elf64_Shdr *shdrs, ElfPltImport **out_imports, size_t *out_n_imports) {
    if (!file || !eh || !shdrs || !out_imports || !out_n_imports) {
        return false;
    }
    *out_imports = NULL;
    *out_n_imports = 0;

    if (eh->e_shstrndx == SHN_UNDEF || eh->e_shstrndx >= eh->e_shnum) {
        return true;
    }

    const Elf64_Shdr *shstr = &shdrs[eh->e_shstrndx];
    if (!range_within((size_t)shstr->sh_offset, (size_t)shstr->sh_size, file_size)) {
        return true;
    }
    const char *shstrs = (const char *)(file + shstr->sh_offset);
    size_t shstr_size = (size_t)shstr->sh_size;

    const Elf64_Shdr *plt = NULL;
    const Elf64_Shdr *plt_sec = NULL;
    size_t plt_idx = SIZE_MAX;
    size_t plt_sec_idx = SIZE_MAX;

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const Elf64_Shdr *sh = &shdrs[i];
        if (sh->sh_name >= shstr_size) {
            continue;
        }
        const char *name = shstrs + sh->sh_name;
        if (strcmp(name, ".plt") == 0) {
            plt = sh;
            plt_idx = i;
        } else if (strcmp(name, ".plt.sec") == 0) {
            plt_sec = sh;
            plt_sec_idx = i;
        }
    }

    ElfPltImport *imports = NULL;
    size_t n_imports = 0;
    size_t imports_cap = 0;

    for (size_t i = 0; i < eh->e_shnum; ++i) {
        const Elf64_Shdr *relsec = &shdrs[i];
        bool is_rela = relsec->sh_type == SHT_RELA;
        bool is_rel = relsec->sh_type == SHT_REL;
        const char *rel_name = NULL;
        bool name_targets_plt = false;
        bool name_targets_plt_sec = false;
        bool info_targets_plt = false;

        if (!is_rela && !is_rel) {
            continue;
        }
        if ((is_rela && relsec->sh_entsize < sizeof(Elf64_Rela)) || (is_rel && relsec->sh_entsize < sizeof(Elf64_Rel))) {
            continue;
        }
        if (!range_within((size_t)relsec->sh_offset, (size_t)relsec->sh_size, file_size)) {
            continue;
        }
        if (relsec->sh_name < shstr_size) {
            rel_name = shstrs + relsec->sh_name;
            if (strncmp(rel_name, ".rela.plt", 9) == 0 || strncmp(rel_name, ".rel.plt", 8) == 0 ||
                strncmp(rel_name, ".rela.iplt", 10) == 0 || strncmp(rel_name, ".rel.iplt", 9) == 0) {
                name_targets_plt = true;
            }
            if (strstr(rel_name, ".plt.sec") != NULL) {
                name_targets_plt_sec = true;
            }
        }
        info_targets_plt = (relsec->sh_info == plt_idx || relsec->sh_info == plt_sec_idx);
        if (!name_targets_plt && !info_targets_plt) {
            continue;
        }

        const Elf64_Shdr *plt_target = plt;
        uint64_t slot_base_index = 1u;
        if (relsec->sh_info == plt_sec_idx || name_targets_plt_sec) {
            plt_target = plt_sec ? plt_sec : plt;
            slot_base_index = 0u;
        } else if (relsec->sh_info == plt_idx) {
            plt_target = plt;
            slot_base_index = 1u;
        }
        if (!plt_target) {
            continue;
        }

        uint32_t slot_size = 16u;
        if (plt_target->sh_entsize != 0 && plt_target->sh_entsize <= UINT32_MAX) {
            slot_size = (uint32_t)plt_target->sh_entsize;
        }
        if (slot_size == 0) {
            slot_size = 16u;
        }

        if (relsec->sh_link >= eh->e_shnum) {
            continue;
        }
        const Elf64_Shdr *symtab = &shdrs[relsec->sh_link];
        if (symtab->sh_entsize < sizeof(Elf64_Sym) ||
            !range_within((size_t)symtab->sh_offset, (size_t)symtab->sh_size, file_size)) {
            continue;
        }
        if (symtab->sh_link >= eh->e_shnum) {
            continue;
        }
        const Elf64_Shdr *strtab = &shdrs[symtab->sh_link];
        if (!range_within((size_t)strtab->sh_offset, (size_t)strtab->sh_size, file_size)) {
            continue;
        }
        const char *strs = (const char *)(file + strtab->sh_offset);
        size_t str_size = (size_t)strtab->sh_size;
        size_t n_sym = (size_t)(symtab->sh_size / symtab->sh_entsize);
        size_t n_rel = (size_t)(relsec->sh_size / relsec->sh_entsize);

        size_t jump_slot_idx = 0;
        for (size_t ri = 0; ri < n_rel; ++ri) {
            uint64_t r_info = 0;

            if (is_rela) {
                const Elf64_Rela *rel = (const Elf64_Rela *)(file + relsec->sh_offset + ri * relsec->sh_entsize);
                r_info = rel->r_info;
            } else {
                const Elf64_Rel *rel = (const Elf64_Rel *)(file + relsec->sh_offset + ri * relsec->sh_entsize);
                r_info = rel->r_info;
            }
            if (ELF64_R_TYPE(r_info) != R_AARCH64_JUMP_SLOT) {
                continue;
            }

            size_t slot_idx = jump_slot_idx++;
            size_t sym_idx = (size_t)ELF64_R_SYM(r_info);
            if (sym_idx >= n_sym) {
                continue;
            }

            const Elf64_Sym *sym = (const Elf64_Sym *)(file + symtab->sh_offset + sym_idx * symtab->sh_entsize);
            if (sym->st_name >= str_size) {
                continue;
            }
            const char *name = strs + sym->st_name;
            if (name[0] == '\0') {
                continue;
            }

            uint64_t addr = plt_target->sh_addr + (slot_base_index + (uint64_t)slot_idx) * (uint64_t)slot_size;
            ElfPltImport entry = {
                .plt_addr = addr,
                .plt_slot_size = slot_size,
                .name = name,
            };
            if (!add_plt_import_entry(&imports, &n_imports, &imports_cap, entry)) {
                free(imports);
                return false;
            }
        }
    }

    *out_imports = imports;
    *out_n_imports = n_imports;
    return true;
}

static uint32_t encode_movz_x0(uint16_t imm16, unsigned hw) {
    return 0xD2800000u | ((uint32_t)(hw & 3u) << 21) | ((uint32_t)imm16 << 5);
}

static uint32_t encode_movk_x0(uint16_t imm16, unsigned hw) {
    return 0xF2800000u | ((uint32_t)(hw & 3u) << 21) | ((uint32_t)imm16 << 5);
}

static uint32_t encode_import_callback_marker(uint8_t callback_id) {
    uint16_t imm16 = (uint16_t)(0xA500u | callback_id);
    return 0xD4400000u | ((uint32_t)imm16 << 5); /* HLT #imm16 */
}

static void emit_return_value_stub(uint8_t *code, size_t stub_pc, uint64_t value) {
    uint16_t h0 = (uint16_t)(value & 0xFFFFu);
    uint16_t h1 = (uint16_t)((value >> 16) & 0xFFFFu);
    uint16_t h2 = (uint16_t)((value >> 32) & 0xFFFFu);
    uint16_t h3 = (uint16_t)((value >> 48) & 0xFFFFu);
    store_u32_le(code + (stub_pc + 0u) * 4u, encode_movz_x0(h0, 0u));
    store_u32_le(code + (stub_pc + 1u) * 4u, encode_movk_x0(h1, 1u));
    store_u32_le(code + (stub_pc + 2u) * 4u, encode_movk_x0(h2, 2u));
    store_u32_le(code + (stub_pc + 3u) * 4u, encode_movk_x0(h3, 3u));
    store_u32_le(code + (stub_pc + 4u) * 4u, 0xD65F03C0u); /* RET */
}

static void emit_import_callback_stub(uint8_t *code, size_t stub_pc, uint8_t callback_id) {
    store_u32_le(code + (stub_pc + 0u) * 4u, encode_import_callback_marker(callback_id));
    store_u32_le(code + (stub_pc + 1u) * 4u, 0xD65F03C0u); /* RET */
    store_u32_le(code + (stub_pc + 2u) * 4u, 0xD503201Fu); /* NOP */
    store_u32_le(code + (stub_pc + 3u) * 4u, 0xD503201Fu); /* NOP */
    store_u32_le(code + (stub_pc + 4u) * 4u, 0xD503201Fu); /* NOP */
}

static bool add_signed_u64(uint64_t base, int64_t delta, uint64_t *out) {
    if (delta >= 0) {
        uint64_t u = (uint64_t)delta;
        if (base > UINT64_MAX - u) {
            return false;
        }
        *out = base + u;
        return true;
    }

    uint64_t u = (uint64_t)(-delta);
    if (base < u) {
        return false;
    }
    *out = base - u;
    return true;
}

typedef struct {
    const char *name;
    bool is_callback;
    uint8_t callback_id;
    uint64_t value;
    size_t stub_pc;
    size_t use_count;
} ElfBranchStub;

static int find_branch_stub_index(const ElfBranchStub *stubs, size_t n_stubs, const char *name, bool is_callback,
                                  uint8_t callback_id, uint64_t value) {
    for (size_t i = 0; i < n_stubs; ++i) {
        if (stubs[i].is_callback != is_callback) {
            continue;
        }
        if (is_callback) {
            if (stubs[i].callback_id != callback_id) {
                continue;
            }
        } else if (stubs[i].value != value) {
            continue;
        }
        if (!name && !stubs[i].name) {
            return (int)i;
        }
        if (name && stubs[i].name && strcmp(name, stubs[i].name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int find_or_add_branch_stub(ElfBranchStub **io_stubs, size_t *io_n, size_t *io_cap, const char *name, bool is_callback,
                                   uint8_t callback_id, uint64_t value) {
    int idx = find_branch_stub_index(*io_stubs, *io_n, name, is_callback, callback_id, value);
    if (idx >= 0) {
        return idx;
    }
    if (*io_n == *io_cap) {
        if (!grow_array((void **)io_stubs, io_cap, sizeof(**io_stubs))) {
            return -1;
        }
    }
    (*io_stubs)[*io_n] = (ElfBranchStub){
        .name = name,
        .is_callback = is_callback,
        .callback_id = callback_id,
        .value = value,
        .stub_pc = 0,
        .use_count = 0,
    };
    idx = (int)(*io_n);
    (*io_n)++;
    return idx;
}

static bool select_branch_stub(size_t pc, int64_t target_pc, uint64_t symbol_vaddr, const ElfPltImport *plt_imports,
                               size_t n_plt_imports, const ElfImportStubSpec *import_specs, size_t n_import_specs,
                               const ElfImportCallbackSpec *callback_specs, size_t n_callback_specs, const char **out_name,
                               bool *out_is_callback, uint8_t *out_callback_id, uint64_t *out_value) {
    *out_name = NULL;
    *out_is_callback = false;
    *out_callback_id = 0;
    *out_value = 0;

    if (!plt_imports || n_plt_imports == 0) {
        return true;
    }
    if (target_pc > INT64_MAX / 4ll || target_pc < INT64_MIN / 4ll) {
        return true;
    }

    int64_t target_byte_off = target_pc * 4ll;
    uint64_t target_vaddr = 0;
    if (!add_signed_u64(symbol_vaddr, target_byte_off, &target_vaddr)) {
        return true;
    }

    const ElfPltImport *imp = find_plt_import_for_target(plt_imports, n_plt_imports, target_vaddr);
    if (!imp) {
        return true;
    }

    uint8_t callback_id = 0;
    if (find_import_callback_id(callback_specs, n_callback_specs, imp->name, &callback_id)) {
        *out_name = imp->name;
        *out_is_callback = true;
        *out_callback_id = callback_id;
        *out_value = 0;
        (void)pc;
        return true;
    }

    if (import_specs && n_import_specs > 0) {
        uint64_t stub_value = 0;
        if (find_import_stub_value(import_specs, n_import_specs, imp->name, &stub_value)) {
            *out_name = imp->name;
            *out_is_callback = false;
            *out_callback_id = 0;
            *out_value = stub_value;
            (void)pc;
            return true;
        }
    }

    (void)pc;
    return true;
}

/*
 * Redirect out-of-range B/BL immediates in extracted symbols to local stubs.
 * Default stub returns X0=0; import-specific stubs can be configured via
 * --elf-import-stub <symbol>=<value>.
 */
static bool patch_elf_out_of_range_branches(uint8_t **io_code, size_t *io_size, uint64_t symbol_vaddr,
                                            const ElfPltImport *plt_imports, size_t n_plt_imports,
                                            const ElfImportStubSpec *import_specs, size_t n_import_specs,
                                            const ElfImportCallbackSpec *callback_specs, size_t n_callback_specs,
                                            const char *trace_path) {
    if (!io_code || !io_size || !*io_code) {
        return false;
    }

    uint8_t *code = *io_code;
    size_t code_size = *io_size;

    if (code_size < 4 || (code_size % 4u) != 0u) {
        return true;
    }

    size_t n_insn = code_size / 4u;
    size_t out_of_range_count = 0;
    ElfBranchStub *stubs = NULL;
    size_t n_stubs = 0;
    size_t stubs_cap = 0;
    size_t local_ret_branch_count = 0;
    size_t import_value_branch_count = 0;
    size_t import_callback_branch_count = 0;

    for (size_t pc = 0; pc < n_insn; ++pc) {
        uint32_t insn = load_u32_le(code + pc * 4u);
        if ((insn & 0x7C000000u) != 0x14000000u) {
            continue; /* not B/BL */
        }
        int64_t imm26 = (int64_t)(insn & 0x03FFFFFFu);
        if ((imm26 & (1ll << 25)) != 0) {
            imm26 -= (1ll << 26);
        }
        int64_t target_pc = (int64_t)pc + imm26;
        if (target_pc < 0 || target_pc >= (int64_t)n_insn) {
            const char *stub_name = NULL;
            bool is_callback = false;
            uint8_t callback_id = 0;
            uint64_t stub_value = 0;
            if (!select_branch_stub(pc, target_pc, symbol_vaddr, plt_imports, n_plt_imports, import_specs, n_import_specs,
                                    callback_specs, n_callback_specs, &stub_name, &is_callback, &callback_id,
                                    &stub_value)) {
                free(stubs);
                return false;
            }
            int stub_idx =
                find_or_add_branch_stub(&stubs, &n_stubs, &stubs_cap, stub_name, is_callback, callback_id, stub_value);
            if (stub_idx < 0) {
                free(stubs);
                fprintf(stderr, "out of memory while building ELF branch stubs\n");
                return false;
            }
            stubs[stub_idx].use_count++;
            if (!stub_name) {
                local_ret_branch_count++;
            } else if (is_callback) {
                import_callback_branch_count++;
            } else {
                import_value_branch_count++;
            }
            out_of_range_count++;
        }
    }

    if (out_of_range_count == 0) {
        free(stubs);
        return true;
    }

    const size_t k_stub_insn = 5u;
    if (n_stubs > SIZE_MAX / k_stub_insn) {
        free(stubs);
        fprintf(stderr, "too many ELF branch stubs\n");
        return false;
    }
    size_t extra_insn = n_stubs * k_stub_insn;
    if (n_insn > SIZE_MAX - extra_insn || (n_insn + extra_insn) > SIZE_MAX / 4u) {
        free(stubs);
        fprintf(stderr, "symbol too large for external branch patching\n");
        return false;
    }

    size_t next_stub_pc = n_insn;
    for (size_t i = 0; i < n_stubs; ++i) {
        stubs[i].stub_pc = next_stub_pc;
        next_stub_pc += k_stub_insn;
    }

    size_t patched_n_insn = n_insn + extra_insn;
    size_t patched_size = patched_n_insn * 4u;
    uint8_t *patched = malloc(patched_size);
    if (!patched) {
        free(stubs);
        perror("malloc");
        return false;
    }
    memcpy(patched, code, code_size);

    size_t patched_count = 0;
    for (size_t pc = 0; pc < n_insn; ++pc) {
        uint32_t insn = load_u32_le(patched + pc * 4u);
        if ((insn & 0x7C000000u) != 0x14000000u) {
            continue;
        }
        int64_t imm26 = (int64_t)(insn & 0x03FFFFFFu);
        if ((imm26 & (1ll << 25)) != 0) {
            imm26 -= (1ll << 26);
        }
        int64_t target_pc = (int64_t)pc + imm26;
        if (target_pc >= 0 && target_pc < (int64_t)n_insn) {
            continue;
        }

        const char *stub_name = NULL;
        bool is_callback = false;
        uint8_t callback_id = 0;
        uint64_t stub_value = 0;
        if (!select_branch_stub(pc, target_pc, symbol_vaddr, plt_imports, n_plt_imports, import_specs, n_import_specs,
                                callback_specs, n_callback_specs, &stub_name, &is_callback, &callback_id, &stub_value)) {
            fprintf(stderr, "failed to select ELF branch stub at pc=%zu\n", pc);
            free(stubs);
            free(patched);
            return false;
        }
        int stub_idx = find_branch_stub_index(stubs, n_stubs, stub_name, is_callback, callback_id, stub_value);
        if (stub_idx < 0) {
            fprintf(stderr, "internal error while patching ELF branch stubs at pc=%zu\n", pc);
            free(stubs);
            free(patched);
            return false;
        }

        int64_t new_imm26 = (int64_t)stubs[stub_idx].stub_pc - (int64_t)pc;
        if (new_imm26 < -(1ll << 25) || new_imm26 > ((1ll << 25) - 1ll)) {
            fprintf(stderr, "external branch trampoline out of range at pc=%zu\n", pc);
            free(stubs);
            free(patched);
            return false;
        }
        uint32_t patched_insn = (insn & 0xFC000000u) | ((uint32_t)new_imm26 & 0x03FFFFFFu);
        store_u32_le(patched + pc * 4u, patched_insn);
        patched_count++;
    }

    for (size_t i = 0; i < n_stubs; ++i) {
        if (stubs[i].is_callback) {
            emit_import_callback_stub(patched, stubs[i].stub_pc, stubs[i].callback_id);
        } else {
            emit_return_value_stub(patched, stubs[i].stub_pc, stubs[i].value);
        }
    }

    free(code);
    *io_code = patched;
    *io_size = patched_size;
    fprintf(stderr,
            "patched %zu out-of-range B/BL branches to %zu local ELF stubs (%zu local-ret, %zu import-value, %zu import-callback)\n",
            patched_count, n_stubs, local_ret_branch_count, import_value_branch_count, import_callback_branch_count);
    if (n_stubs > 0) {
        FILE *trace_file = NULL;
        if (trace_path && trace_path[0] != '\0') {
            trace_file = fopen(trace_path, "a");
            if (!trace_file) {
                fprintf(stderr, "warning: failed to open import trace file '%s': %s\n", trace_path, strerror(errno));
            }
        }
        for (size_t i = 0; i < n_stubs; ++i) {
            if (!stubs[i].name) {
                fprintf(stderr, "  local-ret: branches=%zu\n", stubs[i].use_count);
                if (trace_file) {
                    fprintf(trace_file, "local-ret branches=%zu\n", stubs[i].use_count);
                }
            } else if (stubs[i].is_callback) {
                fprintf(stderr, "  import-callback: symbol=%s op=%s branches=%zu\n", stubs[i].name,
                        import_callback_kind_name(stubs[i].callback_id), stubs[i].use_count);
                if (trace_file) {
                    fprintf(trace_file, "import-callback symbol=%s op=%s branches=%zu\n", stubs[i].name,
                            import_callback_kind_name(stubs[i].callback_id), stubs[i].use_count);
                }
            } else {
                fprintf(stderr, "  import-stub: symbol=%s value=0x%" PRIx64 " branches=%zu\n", stubs[i].name, stubs[i].value,
                        stubs[i].use_count);
                if (trace_file) {
                    fprintf(trace_file, "import-stub symbol=%s value=0x%" PRIx64 " branches=%zu\n", stubs[i].name,
                            stubs[i].value, stubs[i].use_count);
                }
            }
        }
        if (trace_file) {
            fclose(trace_file);
        }
    }
    free(stubs);
    return true;
}

static bool elf_vaddr_to_offset(const Elf64_Phdr *phdrs, size_t n_phdr, uint64_t vaddr, size_t *out_off, size_t *out_avail) {
    for (size_t i = 0; i < n_phdr; ++i) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_filesz == 0) {
            continue;
        }
        if (vaddr < ph->p_vaddr || vaddr >= ph->p_vaddr + ph->p_filesz) {
            continue;
        }
        uint64_t delta = vaddr - ph->p_vaddr;
        if (delta > SIZE_MAX || ph->p_offset > SIZE_MAX || ph->p_filesz > SIZE_MAX) {
            return false;
        }
        size_t off = (size_t)ph->p_offset + (size_t)delta;
        size_t avail = (size_t)ph->p_filesz - (size_t)delta;
        *out_off = off;
        *out_avail = avail;
        return true;
    }
    return false;
}

static bool load_elf_symbol_code(const char *elf_path, const char *symbol, bool has_size_override, size_t size_override,
                                 const ElfImportStubSpec *import_specs, size_t n_import_specs,
                                 const ElfImportCallbackSpec *callback_specs, size_t n_callback_specs,
                                 const char *import_trace_path, uint8_t **out_code, size_t *out_size) {
    size_t file_size = 0;
    uint8_t *file = NULL;
    bool found_zero_size = false;
    bool ok = false;
    ElfPltImport *plt_imports = NULL;
    size_t n_plt_imports = 0;

    if (!elf_path || !symbol || !out_code || !out_size) {
        return false;
    }
    *out_code = NULL;
    *out_size = 0;

    file = read_binary_file(elf_path, "ELF file", &file_size);
    if (!file) {
        return false;
    }
    if (file_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "ELF file too small: %s\n", elf_path);
        goto out;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)file;
    const Elf64_Shdr *shdrs = NULL;
    const Elf64_Phdr *phdrs = NULL;
    size_t n_phdr = 0;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "not an ELF file: %s\n", elf_path);
        goto out;
    }
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "only ELF64 is supported: %s\n", elf_path);
        goto out;
    }
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "only little-endian ELF is supported: %s\n", elf_path);
        goto out;
    }
    if (eh->e_machine != EM_AARCH64) {
        fprintf(stderr, "ELF machine is not AArch64 (e_machine=%u): %s\n", eh->e_machine, elf_path);
        goto out;
    }

    if (eh->e_phnum > 0 && eh->e_phentsize == sizeof(Elf64_Phdr) &&
        range_within((size_t)eh->e_phoff, (size_t)eh->e_phnum * sizeof(Elf64_Phdr), file_size)) {
        phdrs = (const Elf64_Phdr *)(file + eh->e_phoff);
        n_phdr = eh->e_phnum;
    }

    /*
     * Pass 1: section-backed symbol lookup (works when section headers exist).
     * This is useful for unstripped objects with SYMTAB.
     */
    if (eh->e_shnum > 0 && eh->e_shentsize == sizeof(Elf64_Shdr) &&
        range_within((size_t)eh->e_shoff, (size_t)eh->e_shnum * sizeof(Elf64_Shdr), file_size)) {
        shdrs = (const Elf64_Shdr *)(file + eh->e_shoff);
        if (!collect_elf_plt_imports_sections(file, file_size, eh, shdrs, &plt_imports, &n_plt_imports)) {
            fprintf(stderr, "failed to collect ELF PLT import table\n");
            goto out;
        }
        for (size_t sec_i = 0; sec_i < eh->e_shnum; ++sec_i) {
            const Elf64_Shdr *symtab = &shdrs[sec_i];
            if (symtab->sh_type != SHT_SYMTAB && symtab->sh_type != SHT_DYNSYM) {
                continue;
            }
            if (symtab->sh_entsize == 0 || symtab->sh_entsize < sizeof(Elf64_Sym)) {
                continue;
            }
            if (!range_within((size_t)symtab->sh_offset, (size_t)symtab->sh_size, file_size)) {
                continue;
            }
            if (symtab->sh_link >= eh->e_shnum) {
                continue;
            }

            const Elf64_Shdr *strtab = &shdrs[symtab->sh_link];
            if (!range_within((size_t)strtab->sh_offset, (size_t)strtab->sh_size, file_size)) {
                continue;
            }
            const char *strs = (const char *)(file + strtab->sh_offset);
            size_t n_sym = (size_t)(symtab->sh_size / symtab->sh_entsize);

            for (size_t si = 0; si < n_sym; ++si) {
                const uint8_t *sym_ptr = file + symtab->sh_offset + si * symtab->sh_entsize;
                const Elf64_Sym *sym = (const Elf64_Sym *)sym_ptr;
                unsigned sym_type = ELF64_ST_TYPE(sym->st_info);
                if (sym_type != STT_FUNC && sym_type != STT_NOTYPE) {
                    continue;
                }
                if (sym->st_name >= strtab->sh_size) {
                    continue;
                }
                const char *name = strs + sym->st_name;
                if (strcmp(name, symbol) != 0) {
                    continue;
                }
                if (sym->st_shndx == SHN_UNDEF || sym->st_shndx >= eh->e_shnum) {
                    continue;
                }

                const Elf64_Shdr *code_sec = &shdrs[sym->st_shndx];
                if (!range_within((size_t)code_sec->sh_offset, (size_t)code_sec->sh_size, file_size)) {
                    continue;
                }
                if (sym->st_value < code_sec->sh_addr) {
                    continue;
                }

                uint64_t sec_rel = sym->st_value - code_sec->sh_addr;
                size_t code_size = has_size_override ? size_override : (size_t)sym->st_size;
                if (code_size == 0) {
                    found_zero_size = true;
                    continue;
                }
                if (sec_rel > code_sec->sh_size || code_size > (size_t)(code_sec->sh_size - sec_rel)) {
                    continue;
                }

                size_t file_off = (size_t)code_sec->sh_offset + (size_t)sec_rel;
                if (!range_within(file_off, code_size, file_size)) {
                    continue;
                }

                uint8_t *code = malloc(code_size);
                if (!code) {
                    perror("malloc");
                    goto out;
                }
                memcpy(code, file + file_off, code_size);
                if (!patch_elf_out_of_range_branches(&code, &code_size, sym->st_value, plt_imports, n_plt_imports, import_specs,
                                                     n_import_specs, callback_specs, n_callback_specs, import_trace_path)) {
                    free(code);
                    goto out;
                }
                *out_code = code;
                *out_size = code_size;
                ok = true;
                goto out;
            }
        }
    }

    /*
     * Pass 2: dynamic-table symbol lookup (works for stripped shared objects
     * that may not carry usable section headers).
     */
    if (phdrs && n_phdr > 0) {
        const Elf64_Dyn *dyn = NULL;
        size_t dyn_count = 0;
        uint64_t symtab_va = 0;
        uint64_t strtab_va = 0;
        uint64_t strsz = 0;
        uint64_t syment = 0;
        uint64_t hash_va = 0;
        uint64_t gnu_hash_va = 0;
        size_t symtab_off = 0;
        size_t symtab_avail = 0;
        size_t strtab_off = 0;
        size_t strtab_avail = 0;
        size_t n_sym = 0;

        for (size_t i = 0; i < n_phdr; ++i) {
            if (phdrs[i].p_type != PT_DYNAMIC || phdrs[i].p_filesz < sizeof(Elf64_Dyn)) {
                continue;
            }
            if (!range_within((size_t)phdrs[i].p_offset, (size_t)phdrs[i].p_filesz, file_size)) {
                continue;
            }
            dyn = (const Elf64_Dyn *)(file + phdrs[i].p_offset);
            dyn_count = (size_t)(phdrs[i].p_filesz / sizeof(Elf64_Dyn));
            break;
        }

        if (dyn && dyn_count > 0) {
            for (size_t i = 0; i < dyn_count; ++i) {
                if (dyn[i].d_tag == DT_NULL) {
                    break;
                }
                switch (dyn[i].d_tag) {
                    case DT_SYMTAB:
                        symtab_va = (uint64_t)dyn[i].d_un.d_ptr;
                        break;
                    case DT_STRTAB:
                        strtab_va = (uint64_t)dyn[i].d_un.d_ptr;
                        break;
                    case DT_STRSZ:
                        strsz = (uint64_t)dyn[i].d_un.d_val;
                        break;
                    case DT_SYMENT:
                        syment = (uint64_t)dyn[i].d_un.d_val;
                        break;
                    case DT_HASH:
                        hash_va = (uint64_t)dyn[i].d_un.d_ptr;
                        break;
                    case DT_GNU_HASH:
                        gnu_hash_va = (uint64_t)dyn[i].d_un.d_ptr;
                        break;
                    default:
                        break;
                }
            }
        }

        if (symtab_va != 0 && strtab_va != 0 && syment >= sizeof(Elf64_Sym) &&
            elf_vaddr_to_offset(phdrs, n_phdr, symtab_va, &symtab_off, &symtab_avail) &&
            elf_vaddr_to_offset(phdrs, n_phdr, strtab_va, &strtab_off, &strtab_avail)) {
            if (strsz != 0 && strsz < strtab_avail) {
                strtab_avail = (size_t)strsz;
            }
            if (!range_within(strtab_off, strtab_avail, file_size)) {
                strtab_avail = 0;
            }
            if (!range_within(symtab_off, symtab_avail, file_size)) {
                symtab_avail = 0;
            }

            if (symtab_avail >= syment && strtab_avail > 0) {
                n_sym = symtab_avail / (size_t)syment;

                if (hash_va != 0) {
                    size_t hash_off = 0;
                    size_t hash_avail = 0;
                    if (elf_vaddr_to_offset(phdrs, n_phdr, hash_va, &hash_off, &hash_avail) &&
                        range_within(hash_off, 8, file_size)) {
                        const uint32_t *hash_words = (const uint32_t *)(file + hash_off);
                        uint32_t nchain = hash_words[1];
                        if (nchain > 0 && (size_t)nchain < n_sym) {
                            n_sym = nchain;
                        }
                    }
                } else if (gnu_hash_va != 0) {
                    size_t ghash_off = 0;
                    size_t ghash_avail = 0;
                    if (elf_vaddr_to_offset(phdrs, n_phdr, gnu_hash_va, &ghash_off, &ghash_avail) &&
                        range_within(ghash_off, 16, file_size)) {
                        const uint32_t *hdr = (const uint32_t *)(file + ghash_off);
                        uint32_t nbuckets = hdr[0];
                        uint32_t symoffset = hdr[1];
                        uint32_t bloom_size = hdr[2];
                        size_t buckets_off = ghash_off + 16 + (size_t)bloom_size * sizeof(Elf64_Xword);
                        if (nbuckets > 0 && range_within(buckets_off, (size_t)nbuckets * 4u, file_size)) {
                            const uint32_t *buckets = (const uint32_t *)(file + buckets_off);
                            uint32_t max_bucket = 0;
                            for (uint32_t b = 0; b < nbuckets; ++b) {
                                if (buckets[b] > max_bucket) {
                                    max_bucket = buckets[b];
                                }
                            }
                            if (max_bucket > symoffset && (size_t)max_bucket < n_sym) {
                                n_sym = (size_t)max_bucket + 16384u;
                                if (n_sym > symtab_avail / (size_t)syment) {
                                    n_sym = symtab_avail / (size_t)syment;
                                }
                            }
                        }
                    }
                }

                const char *strs = (const char *)(file + strtab_off);
                for (size_t si = 0; si < n_sym; ++si) {
                    const uint8_t *sym_ptr = file + symtab_off + si * (size_t)syment;
                    const Elf64_Sym *sym = (const Elf64_Sym *)sym_ptr;
                    unsigned sym_type = ELF64_ST_TYPE(sym->st_info);
                    if (sym_type != STT_FUNC && sym_type != STT_NOTYPE) {
                        continue;
                    }
                    if (sym->st_name >= strtab_avail) {
                        continue;
                    }
                    const char *name = strs + sym->st_name;
                    if (strcmp(name, symbol) != 0) {
                        continue;
                    }
                    if (sym->st_value == 0) {
                        continue;
                    }

                    size_t code_size = has_size_override ? size_override : (size_t)sym->st_size;
                    if (code_size == 0) {
                        found_zero_size = true;
                        continue;
                    }

                    size_t code_off = 0;
                    size_t code_avail = 0;
                    if (!elf_vaddr_to_offset(phdrs, n_phdr, sym->st_value, &code_off, &code_avail)) {
                        continue;
                    }
                    if (code_size > code_avail || !range_within(code_off, code_size, file_size)) {
                        continue;
                    }

                    uint8_t *code = malloc(code_size);
                    if (!code) {
                        perror("malloc");
                        goto out;
                    }
                    memcpy(code, file + code_off, code_size);
                    if (!patch_elf_out_of_range_branches(&code, &code_size, sym->st_value, plt_imports, n_plt_imports,
                                                         import_specs, n_import_specs, callback_specs, n_callback_specs,
                                                         import_trace_path)) {
                        free(code);
                        goto out;
                    }
                    *out_code = code;
                    *out_size = code_size;
                    ok = true;
                    goto out;
                }
            }
        }
    }

    if (found_zero_size && !has_size_override) {
        fprintf(stderr, "symbol '%s' in %s has size 0; pass --elf-size to override\n", symbol, elf_path);
    } else {
        fprintf(stderr, "failed to locate runnable symbol '%s' in %s\n", symbol, elf_path);
    }

out:
    free(plt_imports);
    free(file);
    return ok;
}

static bool parse_mem_write_file_spec(const char *s, MemWriteSpec *out) {
    const char *sep = strchr(s, ':');
    if (!sep || sep == s || sep[1] == '\0') {
        return false;
    }

    size_t addr_len = (size_t)(sep - s);
    if (addr_len >= 64) {
        return false;
    }
    char addr_buf[64];
    memcpy(addr_buf, s, addr_len);
    addr_buf[addr_len] = '\0';

    uint64_t addr = 0;
    if (!parse_u64_arg(addr_buf, &addr)) {
        return false;
    }

    const char *path = sep + 1;
    size_t len = 0;
    uint8_t *bytes = read_binary_file(path, "memory blob file", &len);
    if (!bytes) {
        return false;
    }
    if (len == 0) {
        fprintf(stderr, "memory blob file '%s' is empty\n", path);
        free(bytes);
        return false;
    }

    out->addr = addr;
    out->bytes = bytes;
    out->len = len;
    return true;
}

static bool parse_mem_read_file_spec(const char *s, MemReadSpec *out) {
    const char *sep1 = strchr(s, ':');
    if (!sep1 || sep1 == s || sep1[1] == '\0') {
        return false;
    }
    const char *sep2 = strchr(sep1 + 1, ':');
    if (!sep2 || sep2 == sep1 + 1 || sep2[1] == '\0') {
        return false;
    }

    size_t addr_len = (size_t)(sep1 - s);
    size_t len_len = (size_t)(sep2 - (sep1 + 1));
    if (addr_len >= 64 || len_len >= 64) {
        return false;
    }

    char addr_buf[64];
    char len_buf[64];
    memcpy(addr_buf, s, addr_len);
    addr_buf[addr_len] = '\0';
    memcpy(len_buf, sep1 + 1, len_len);
    len_buf[len_len] = '\0';

    uint64_t addr = 0;
    uint64_t len_u64 = 0;
    if (!parse_u64_arg(addr_buf, &addr) || !parse_u64_arg(len_buf, &len_u64)) {
        return false;
    }
    if (len_u64 == 0 || len_u64 > SIZE_MAX) {
        return false;
    }

    out->addr = addr;
    out->len = (size_t)len_u64;
    out->out_path = sep2 + 1;
    return true;
}

static bool parse_reg_assignment(const char *s, TinyDbtCpuState *state) {
    const char *eq = strchr(s, '=');
    if (!eq || eq == s || eq[1] == '\0') {
        return false;
    }

    size_t reg_len = (size_t)(eq - s);
    char reg[16];
    if (reg_len >= sizeof(reg)) {
        return false;
    }
    memcpy(reg, s, reg_len);
    reg[reg_len] = '\0';

    uint64_t value = 0;
    if (!parse_u64_arg(eq + 1, &value)) {
        return false;
    }

    if (strcmp(reg, "sp") == 0) {
        state->sp = value;
        return true;
    }
    if (strcmp(reg, "pc") == 0) {
        state->pc = value;
        return true;
    }
    if (strcmp(reg, "nzcv") == 0) {
        if (value > 0xFFFFFFFFull) {
            return false;
        }
        state->nzcv = (uint32_t)value;
        return true;
    }
    if (strcmp(reg, "heap_base") == 0) {
        state->heap_base = value;
        return true;
    }
    if (strcmp(reg, "heap_brk") == 0) {
        state->heap_brk = value;
        return true;
    }
    if (strcmp(reg, "heap_last_ptr") == 0) {
        state->heap_last_ptr = value;
        return true;
    }
    if (strcmp(reg, "heap_last_size") == 0) {
        state->heap_last_size = value;
        return true;
    }
    if (reg[0] == 'x' && reg[1] != '\0') {
        char *end = NULL;
        errno = 0;
        unsigned long idx = strtoul(reg + 1, &end, 10);
        if (errno != 0 || end == reg + 1 || *end != '\0' || idx > 30) {
            return false;
        }
        state->x[idx] = value;
        return true;
    }
    return false;
}

static uint32_t parse_u32_hex(const char *s) {
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 16);
    if (errno != 0 || end == s || *end != '\0' || v > 0xFFFFFFFFul) {
        fprintf(stderr, "bad opcode: %s\n", s);
        exit(2);
    }
    return (uint32_t)v;
}

static void print_mem_dump(uint64_t addr, const uint8_t *bytes, size_t len) {
    uint64_t end_addr = addr + (uint64_t)len - 1u;
    printf("mem[0x%" PRIx64 "..0x%" PRIx64 "] =", addr, end_addr);
    for (size_t i = 0; i < len; ++i) {
        printf(" %02x", bytes[i]);
    }
    printf("\n");
}

static void print_state_snapshot(const char *label, const TinyDbtCpuState *state) {
    if (!state) {
        return;
    }
    fprintf(stderr,
            "trace:%s pc=0x%" PRIx64 " sp=0x%" PRIx64 " nzcv=0x%08" PRIx32
            " x0=0x%" PRIx64 " x1=0x%" PRIx64 " x2=0x%" PRIx64 " x3=0x%" PRIx64
            " dispatch_version=%" PRIu64 " exit_reason=%" PRIu64 "\n",
            label, state->pc, state->sp, state->nzcv, state->x[0], state->x[1], state->x[2], state->x[3],
            state->dispatch_version, state->exit_reason);
}

static bool write_binary_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to open output file '%s': %s\n", path, strerror(errno));
        return false;
    }
    size_t n = fwrite(data, 1, len, f);
    if (n != len) {
        fprintf(stderr, "failed to write output file '%s': %s\n", path, strerror(errno));
        fclose(f);
        return false;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "failed to close output file '%s': %s\n", path, strerror(errno));
        return false;
    }
    return true;
}

static void free_cli_options(CliOptions *opts) {
    if (!opts) {
        return;
    }
    for (size_t i = 0; i < opts->n_elf_import_stubs; ++i) {
        free(opts->elf_import_stubs[i].name);
        opts->elf_import_stubs[i].name = NULL;
    }
    free(opts->elf_import_stubs);
    opts->elf_import_stubs = NULL;
    opts->n_elf_import_stubs = 0;
    opts->elf_import_stubs_cap = 0;

    for (size_t i = 0; i < opts->n_elf_import_callbacks; ++i) {
        free(opts->elf_import_callbacks[i].name);
        opts->elf_import_callbacks[i].name = NULL;
    }
    free(opts->elf_import_callbacks);
    opts->elf_import_callbacks = NULL;
    opts->n_elf_import_callbacks = 0;
    opts->elf_import_callbacks_cap = 0;

    for (size_t i = 0; i < opts->n_mem_writes; ++i) {
        free(opts->mem_writes[i].bytes);
        opts->mem_writes[i].bytes = NULL;
    }
    free(opts->mem_writes);
    opts->mem_writes = NULL;
    opts->n_mem_writes = 0;
    opts->mem_writes_cap = 0;

    free(opts->mem_reads);
    opts->mem_reads = NULL;
    opts->n_mem_reads = 0;
    opts->mem_reads_cap = 0;
}

static void print_usage(FILE *out, const char *prog) {
    fprintf(out,
            "usage: %s [options] <A64 opcode hex> [more...]\n"
            "   or: %s [options] --code-file <aarch64_le_code.bin>\n"
            "   or: %s [options] --elf-file <lib.so> --elf-symbol <name> [--elf-size <bytes>]\n"
            "options:\n"
            "  -h, --help                      show help\n"
            "  --code-file <path>              load raw AArch64 little-endian instruction bytes\n"
            "  --elf-file <path>               load code bytes from an AArch64 ELF image\n"
            "  --elf-symbol <name>             symbol name to extract from --elf-file\n"
            "  --elf-size <bytes>              override symbol byte size (required for size=0 symbols)\n"
            "  --elf-import-stub <sym=value>   return fixed X0 value when branching to PLT import symbol\n"
            "  --elf-import-callback <sym=op>  host callback op (ret_x0..ret_x7, add_x0_x1, sub_x0_x1, ret_sp, nonnull_x0, guest_alloc_x0, guest_free_x0, guest_calloc_x0_x1, guest_realloc_x0_x1, guest_memcpy_x0_x1_x2, guest_memset_x0_x1_x2, guest_memcmp_x0_x1_x2, guest_memmove_x0_x1_x2, guest_strnlen_x0_x1, guest_strlen_x0, guest_strcmp_x0_x1, guest_strncmp_x0_x1_x2, guest_strcpy_x0_x1, guest_strncpy_x0_x1_x2, guest_strchr_x0_x1)\n"
            "  --elf-import-trace <path>       append per-symbol import patching summary\n"
            "  --pc-bytes <n>                  set initial state.pc before run\n"
            "  --set-reg <name=value>          set initial register/state (x0..x30, sp, pc, nzcv, heap_*)\n"
            "  --trace-state                   print a compact CPU-state snapshot before/after run\n"
            "  --mem-write <addr:hexbytes>     write bytes into guest memory before run\n"
            "  --mem-write-file <addr:path>    load bytes from file into guest memory before run\n"
            "  --mem-read <addr:len>           dump bytes from guest memory after run\n"
            "  --mem-read-file <addr:len:path> write bytes from guest memory to file after run\n"
            "  --invalidate-dispatch           bump dispatch version before run\n"
            "  --invalidate-all-slots          invalidate all dispatch slots before run\n"
            "  --invalidate-pc-indexes <list>  invalidate specific slots (comma-separated)\n"
            "  --debug-exit                    print per-attempt exit/debug state\n"
            "  --max-retries <n>               override version-miss retry budget (1..4096)\n"
            "  --log-unsupported <path>        append executed unsupported opcodes to file\n"
            "example:\n"
            "  %s D28000E0 91008C00 D65F03C0\n"
            "  %s --code-file /tmp/prog.bin\n"
            "  %s --elf-file /tmp/libfoo.so --elf-symbol tiny_func\n"
            "  %s --pc-bytes 4 --code-file /tmp/prog.bin\n"
            "  %s --set-reg x0=1337 D65F03C0\n"
            "  %s --trace-state D28000E0 91008C00 D65F03C0\n"
            "  %s --mem-write 0x20:8877665544332211 --mem-read 0x20:8 D2800401 F9400020 D65F03C0\n"
            "  %s --mem-write-file 0x20:/tmp/mem.bin --mem-read 0x20:8 D2800401 F9400020 D65F03C0\n"
            "  %s --mem-read-file 0x20:8:/tmp/out.bin D2800401 F9400020 D65F03C0\n"
            "  %s --invalidate-dispatch D2800540 D65F03C0\n"
            "  %s --elf-file /tmp/libfoo.so --elf-symbol JNI_OnLoad --elf-import-stub malloc=0\n"
            "  %s --elf-file /tmp/libfoo.so --elf-symbol JNI_OnLoad --elf-import-callback malloc=ret_x0\n"
            "  %s --elf-file /tmp/libfoo.so --elf-symbol JNI_OnLoad --elf-import-trace /tmp/import_trace.log\n"
            "  %s --invalidate-pc-indexes=3 D2800181 D61F0020 D2800000 D2800540 91000400 D65F03C0\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

static bool parse_cli_options(int argc, char **argv, CliOptions *opts) {
    memset(opts, 0, sizeof(*opts));
    tiny_dbt_state_init(&opts->initial_state);
    opts->first_opcode_arg = 1;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--") == 0) {
            opts->first_opcode_arg = i + 1;
            return true;
        }
        if (arg[0] != '-') {
            opts->first_opcode_arg = i;
            return true;
        }

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            opts->show_help = true;
            opts->first_opcode_arg = argc;
            return true;
        }
        if (strncmp(arg, "--code-file=", 12) == 0) {
            const char *value = arg + 12;
            if (value[0] == '\0') {
                fprintf(stderr, "missing value for --code-file\n");
                return false;
            }
            opts->code_file = value;
            continue;
        }
        if (strcmp(arg, "--code-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --code-file\n");
                return false;
            }
            opts->code_file = argv[++i];
            continue;
        }
        if (strncmp(arg, "--elf-file=", 11) == 0) {
            const char *value = arg + 11;
            if (value[0] == '\0') {
                fprintf(stderr, "missing value for --elf-file\n");
                return false;
            }
            opts->elf_file = value;
            continue;
        }
        if (strcmp(arg, "--elf-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --elf-file\n");
                return false;
            }
            opts->elf_file = argv[++i];
            continue;
        }
        if (strncmp(arg, "--elf-symbol=", 13) == 0) {
            const char *value = arg + 13;
            if (value[0] == '\0') {
                fprintf(stderr, "missing value for --elf-symbol\n");
                return false;
            }
            opts->elf_symbol = value;
            continue;
        }
        if (strcmp(arg, "--elf-symbol") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --elf-symbol\n");
                return false;
            }
            opts->elf_symbol = argv[++i];
            continue;
        }
        if (strncmp(arg, "--elf-size=", 11) == 0) {
            const char *value = arg + 11;
            if (!parse_size_arg(value, &opts->elf_size_override)) {
                fprintf(stderr, "invalid value for --elf-size: %s\n", value);
                return false;
            }
            opts->has_elf_size_override = true;
            continue;
        }
        if (strcmp(arg, "--elf-size") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --elf-size\n");
                return false;
            }
            const char *value = argv[++i];
            if (!parse_size_arg(value, &opts->elf_size_override)) {
                fprintf(stderr, "invalid value for --elf-size: %s\n", value);
                return false;
            }
            opts->has_elf_size_override = true;
            continue;
        }
        if (strncmp(arg, "--elf-import-stub=", 18) == 0) {
            ElfImportStubSpec spec = {0};
            const char *value = arg + 18;
            if (!parse_elf_import_stub_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --elf-import-stub: %s\n", value);
                return false;
            }
            if (!add_elf_import_stub_spec(opts, spec)) {
                free(spec.name);
                fprintf(stderr, "out of memory while parsing --elf-import-stub\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--elf-import-stub") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --elf-import-stub\n");
                return false;
            }
            ElfImportStubSpec spec = {0};
            const char *value = argv[++i];
            if (!parse_elf_import_stub_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --elf-import-stub: %s\n", value);
                return false;
            }
            if (!add_elf_import_stub_spec(opts, spec)) {
                free(spec.name);
                fprintf(stderr, "out of memory while parsing --elf-import-stub\n");
                return false;
            }
            continue;
        }
        if (strncmp(arg, "--elf-import-callback=", 22) == 0) {
            ElfImportCallbackSpec spec = {0};
            const char *value = arg + 22;
            if (!parse_elf_import_callback_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --elf-import-callback: %s\n", value);
                return false;
            }
            if (!add_elf_import_callback_spec(opts, spec)) {
                free(spec.name);
                fprintf(stderr, "out of memory while parsing --elf-import-callback\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--elf-import-callback") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --elf-import-callback\n");
                return false;
            }
            ElfImportCallbackSpec spec = {0};
            const char *value = argv[++i];
            if (!parse_elf_import_callback_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --elf-import-callback: %s\n", value);
                return false;
            }
            if (!add_elf_import_callback_spec(opts, spec)) {
                free(spec.name);
                fprintf(stderr, "out of memory while parsing --elf-import-callback\n");
                return false;
            }
            continue;
        }
        if (strncmp(arg, "--elf-import-trace=", 19) == 0) {
            const char *value = arg + 19;
            if (value[0] == '\0') {
                fprintf(stderr, "missing value for --elf-import-trace\n");
                return false;
            }
            opts->elf_import_trace_path = value;
            continue;
        }
        if (strcmp(arg, "--elf-import-trace") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --elf-import-trace\n");
                return false;
            }
            opts->elf_import_trace_path = argv[++i];
            continue;
        }
        if (strncmp(arg, "--pc-bytes=", 11) == 0) {
            uint64_t value = 0;
            if (!parse_u64_arg(arg + 11, &value)) {
                fprintf(stderr, "invalid value for --pc-bytes: %s\n", arg + 11);
                return false;
            }
            opts->initial_state.pc = value;
            opts->has_initial_state = true;
            continue;
        }
        if (strcmp(arg, "--pc-bytes") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --pc-bytes\n");
                return false;
            }
            uint64_t value = 0;
            if (!parse_u64_arg(argv[++i], &value)) {
                fprintf(stderr, "invalid value for --pc-bytes: %s\n", argv[i]);
                return false;
            }
            opts->initial_state.pc = value;
            opts->has_initial_state = true;
            continue;
        }
        if (strncmp(arg, "--set-reg=", 10) == 0) {
            const char *value = arg + 10;
            if (!parse_reg_assignment(value, &opts->initial_state)) {
                fprintf(stderr, "invalid value for --set-reg: %s\n", value);
                return false;
            }
            opts->has_initial_state = true;
            continue;
        }
        if (strcmp(arg, "--set-reg") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --set-reg\n");
                return false;
            }
            const char *value = argv[++i];
            if (!parse_reg_assignment(value, &opts->initial_state)) {
                fprintf(stderr, "invalid value for --set-reg: %s\n", value);
                return false;
            }
            opts->has_initial_state = true;
            continue;
        }
        if (strcmp(arg, "--trace-state") == 0) {
            opts->trace_state = true;
            continue;
        }
        if (strncmp(arg, "--mem-write=", 12) == 0) {
            MemWriteSpec spec = {0};
            const char *value = arg + 12;
            if (!parse_mem_write_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-write: %s\n", value);
                return false;
            }
            if (!add_mem_write_spec(opts, spec)) {
                free(spec.bytes);
                fprintf(stderr, "out of memory while parsing --mem-write\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--mem-write") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --mem-write\n");
                return false;
            }
            MemWriteSpec spec = {0};
            const char *value = argv[++i];
            if (!parse_mem_write_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-write: %s\n", value);
                return false;
            }
            if (!add_mem_write_spec(opts, spec)) {
                free(spec.bytes);
                fprintf(stderr, "out of memory while parsing --mem-write\n");
                return false;
            }
            continue;
        }
        if (strncmp(arg, "--mem-write-file=", 17) == 0) {
            MemWriteSpec spec = {0};
            const char *value = arg + 17;
            if (!parse_mem_write_file_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-write-file: %s\n", value);
                return false;
            }
            if (!add_mem_write_spec(opts, spec)) {
                free(spec.bytes);
                fprintf(stderr, "out of memory while parsing --mem-write-file\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--mem-write-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --mem-write-file\n");
                return false;
            }
            MemWriteSpec spec = {0};
            const char *value = argv[++i];
            if (!parse_mem_write_file_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-write-file: %s\n", value);
                return false;
            }
            if (!add_mem_write_spec(opts, spec)) {
                free(spec.bytes);
                fprintf(stderr, "out of memory while parsing --mem-write-file\n");
                return false;
            }
            continue;
        }
        if (strncmp(arg, "--mem-read=", 11) == 0) {
            MemReadSpec spec = {0};
            const char *value = arg + 11;
            if (!parse_mem_read_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-read: %s\n", value);
                return false;
            }
            if (!add_mem_read_spec(opts, spec)) {
                fprintf(stderr, "out of memory while parsing --mem-read\n");
                return false;
            }
            continue;
        }
        if (strncmp(arg, "--mem-read-file=", 16) == 0) {
            MemReadSpec spec = {0};
            const char *value = arg + 16;
            if (!parse_mem_read_file_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-read-file: %s\n", value);
                return false;
            }
            if (!add_mem_read_spec(opts, spec)) {
                fprintf(stderr, "out of memory while parsing --mem-read-file\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--mem-read-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --mem-read-file\n");
                return false;
            }
            MemReadSpec spec = {0};
            const char *value = argv[++i];
            if (!parse_mem_read_file_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-read-file: %s\n", value);
                return false;
            }
            if (!add_mem_read_spec(opts, spec)) {
                fprintf(stderr, "out of memory while parsing --mem-read-file\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--mem-read") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --mem-read\n");
                return false;
            }
            MemReadSpec spec = {0};
            const char *value = argv[++i];
            if (!parse_mem_read_spec(value, &spec)) {
                fprintf(stderr, "invalid value for --mem-read: %s\n", value);
                return false;
            }
            if (!add_mem_read_spec(opts, spec)) {
                fprintf(stderr, "out of memory while parsing --mem-read\n");
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--invalidate-dispatch") == 0) {
            opts->invalidate_dispatch = true;
            continue;
        }
        if (strcmp(arg, "--invalidate-all-slots") == 0) {
            opts->invalidate_all_slots = true;
            continue;
        }
        if (strncmp(arg, "--invalidate-pc-indexes=", 24) == 0) {
            const char *value = arg + 24;
            if (value[0] == '\0') {
                fprintf(stderr, "missing value for --invalidate-pc-indexes\n");
                return false;
            }
            opts->invalidate_pc_indexes = value;
            continue;
        }
        if (strcmp(arg, "--invalidate-pc-indexes") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --invalidate-pc-indexes\n");
                return false;
            }
            opts->invalidate_pc_indexes = argv[++i];
            continue;
        }
        if (strncmp(arg, "--max-retries=", 14) == 0) {
            const char *value = arg + 14;
            if (!parse_max_retries(value, &opts->max_retries)) {
                fprintf(stderr, "invalid value for --max-retries: %s\n", value);
                return false;
            }
            opts->has_max_retries = true;
            continue;
        }
        if (strcmp(arg, "--max-retries") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --max-retries\n");
                return false;
            }
            const char *value = argv[++i];
            if (!parse_max_retries(value, &opts->max_retries)) {
                fprintf(stderr, "invalid value for --max-retries: %s\n", value);
                return false;
            }
            opts->has_max_retries = true;
            continue;
        }
        if (strcmp(arg, "--debug-exit") == 0) {
            opts->debug_exit = true;
            continue;
        }
        if (strncmp(arg, "--log-unsupported=", 18) == 0) {
            const char *value = arg + 18;
            if (value[0] == '\0') {
                fprintf(stderr, "missing value for --log-unsupported\n");
                return false;
            }
            opts->unsupported_log_path = value;
            continue;
        }
        if (strcmp(arg, "--log-unsupported") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --log-unsupported\n");
                return false;
            }
            opts->unsupported_log_path = argv[++i];
            continue;
        }

        fprintf(stderr, "unknown option: %s\n", arg);
        return false;
    }

    opts->first_opcode_arg = argc;
    return true;
}

int main(int argc, char **argv) {
    CliOptions opts = {0};
    TinyDbt *dbt = NULL;
    uint64_t x0 = 0;
    int rc = 1;
    if (!parse_cli_options(argc, argv, &opts)) {
        free_cli_options(&opts);
        print_usage(stderr, argv[0]);
        return 2;
    }
    if (opts.show_help) {
        print_usage(stdout, argv[0]);
        rc = 0;
        goto out;
    }
    if (opts.code_file && opts.elf_file) {
        fprintf(stderr, "--code-file cannot be combined with --elf-file\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (opts.elf_symbol && !opts.elf_file) {
        fprintf(stderr, "--elf-symbol requires --elf-file\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (opts.elf_file && !opts.elf_symbol) {
        fprintf(stderr, "--elf-file requires --elf-symbol\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (opts.has_elf_size_override && !opts.elf_file) {
        fprintf(stderr, "--elf-size requires --elf-file/--elf-symbol\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (opts.n_elf_import_stubs > 0 && !opts.elf_file) {
        fprintf(stderr, "--elf-import-stub requires --elf-file/--elf-symbol\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (opts.n_elf_import_callbacks > 0 && !opts.elf_file) {
        fprintf(stderr, "--elf-import-callback requires --elf-file/--elf-symbol\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (opts.elf_import_trace_path && !opts.elf_file) {
        fprintf(stderr, "--elf-import-trace requires --elf-file/--elf-symbol\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if ((opts.code_file || opts.elf_file) && opts.first_opcode_arg < argc) {
        fprintf(stderr, "--code-file/--elf-file cannot be combined with inline opcode arguments\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }
    if (!opts.code_file && !opts.elf_file && opts.first_opcode_arg >= argc) {
        fprintf(stderr, "missing A64 opcode list\n");
        print_usage(stderr, argv[0]);
        rc = 2;
        goto out;
    }

    if (opts.elf_file) {
        size_t code_size = 0;
        uint8_t *code = NULL;
        if (!load_elf_symbol_code(opts.elf_file, opts.elf_symbol, opts.has_elf_size_override, opts.elf_size_override,
                                  opts.elf_import_stubs, opts.n_elf_import_stubs, opts.elf_import_callbacks,
                                  opts.n_elf_import_callbacks, opts.elf_import_trace_path, &code, &code_size)) {
            goto out;
        }
        dbt = tiny_dbt_create_from_bytes(code, code_size);
        free(code);
    } else if (opts.code_file) {
        size_t code_size = 0;
        uint8_t *code = read_binary_file(opts.code_file, "code file", &code_size);
        if (!code) {
            goto out;
        }
        dbt = tiny_dbt_create_from_bytes(code, code_size);
        free(code);
    } else {
        size_t n_insn = (size_t)(argc - opts.first_opcode_arg);
        uint32_t *insns = calloc(n_insn, sizeof(*insns));
        if (!insns) {
            perror("calloc");
            goto out;
        }
        for (size_t i = 0; i < n_insn; ++i) {
            insns[i] = parse_u32_hex(argv[(size_t)opts.first_opcode_arg + i]);
        }
        dbt = tiny_dbt_create(insns, n_insn);
        free(insns);
    }

    if (!dbt) {
        fprintf(stderr, "tiny_dbt_create failed: %s\n", tiny_dbt_last_error(NULL));
        goto out;
    }

    for (size_t i = 0; i < opts.n_mem_writes; ++i) {
        if (!tiny_dbt_guest_mem_write(dbt, opts.mem_writes[i].addr, opts.mem_writes[i].bytes, opts.mem_writes[i].len)) {
            fprintf(stderr, "tiny_dbt_guest_mem_write failed: %s\n", tiny_dbt_last_error(dbt));
            goto out;
        }
    }

    TinyDbtRunOptions run_opts = {0};
    run_opts.invalidate_dispatch = opts.invalidate_dispatch || env_flag_enabled("TINY_DBT_INVALIDATE_BEFORE_RUN");
    run_opts.invalidate_all_slots = opts.invalidate_all_slots || env_flag_enabled("TINY_DBT_INVALIDATE_ALL_SLOTS");
    run_opts.debug_exit = opts.debug_exit || env_flag_enabled("TINY_DBT_DEBUG_EXIT");
    if (opts.has_max_retries) {
        run_opts.max_retries = opts.max_retries;
    }
    run_opts.invalidate_pc_indexes = opts.invalidate_pc_indexes;
    if (!run_opts.invalidate_pc_indexes || run_opts.invalidate_pc_indexes[0] == '\0') {
        run_opts.invalidate_pc_indexes = getenv("TINY_DBT_INVALIDATE_PC_INDEXES");
    }
    run_opts.unsupported_log_path = opts.unsupported_log_path;
    if (!run_opts.unsupported_log_path || run_opts.unsupported_log_path[0] == '\0') {
        run_opts.unsupported_log_path = getenv("TINY_DBT_LOG_UNSUPPORTED");
    }

    bool trace_state = opts.trace_state || env_flag_enabled("TINY_DBT_TRACE_STATE");

    bool ok = false;
    if (opts.has_initial_state || trace_state) {
        TinyDbtCpuState state = opts.initial_state;
        if (trace_state) {
            print_state_snapshot("before", &state);
        }
        ok = tiny_dbt_run_with_state(dbt, &state, &run_opts, &x0);
        if (trace_state) {
            print_state_snapshot("after", &state);
        }
    } else {
        ok = tiny_dbt_run(dbt, &run_opts, &x0);
    }
    if (ok) {
        printf("x0 = %" PRIu64 " (0x%" PRIx64 ")\n", x0, x0);
    } else {
        fprintf(stderr, "tiny_dbt_run failed: %s\n", tiny_dbt_last_error(dbt));
    }

    if (ok) {
        for (size_t i = 0; i < opts.n_mem_reads; ++i) {
            uint8_t *buf = malloc(opts.mem_reads[i].len);
            if (!buf) {
                perror("malloc");
                ok = false;
                break;
            }
            if (!tiny_dbt_guest_mem_read(dbt, opts.mem_reads[i].addr, buf, opts.mem_reads[i].len)) {
                fprintf(stderr, "tiny_dbt_guest_mem_read failed: %s\n", tiny_dbt_last_error(dbt));
                free(buf);
                ok = false;
                break;
            }
            if (opts.mem_reads[i].out_path && opts.mem_reads[i].out_path[0] != '\0') {
                if (!write_binary_file(opts.mem_reads[i].out_path, buf, opts.mem_reads[i].len)) {
                    free(buf);
                    ok = false;
                    break;
                }
                printf("mem[0x%" PRIx64 "..0x%" PRIx64 "] -> %s (%zu bytes)\n", opts.mem_reads[i].addr,
                       opts.mem_reads[i].addr + (uint64_t)opts.mem_reads[i].len - 1u, opts.mem_reads[i].out_path,
                       opts.mem_reads[i].len);
            } else {
                print_mem_dump(opts.mem_reads[i].addr, buf, opts.mem_reads[i].len);
            }
            free(buf);
        }
    }

    rc = ok ? 0 : 1;
out:
    tiny_dbt_destroy(dbt);
    free_cli_options(&opts);
    return rc;
}
