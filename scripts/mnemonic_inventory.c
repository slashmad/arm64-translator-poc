#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t mask;
    uint32_t value;
    char *name;
    uint64_t hits;
} Rule;

typedef struct {
    char *name;
    uint64_t hits;
} MnemonicStat;

typedef struct {
    uint64_t skipped_zero_words;
    uint64_t total_words;
    uint64_t matched_words;
    uint64_t unmatched_words;
    uint64_t trailing_bytes;
    uint64_t files_processed;
    uint64_t bucket11[2048];
    uint64_t bucket7[128];
    uint32_t example11[2048];
    uint32_t example7[128];
    bool has_example11[2048];
    bool has_example7[128];
} Stats;

static void die(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

static uint32_t parse_u32_or_die(const char *tok) {
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(tok, &end, 0);
    if (errno != 0 || end == tok || *end != '\0' || v > 0xFFFFFFFFul) {
        fprintf(stderr, "error: invalid 32-bit value: '%s'\n", tok);
        exit(1);
    }
    return (uint32_t)v;
}

static char *xstrdup_or_die(const char *s) {
    size_t n;
    char *out;
    if (!s) {
        die("xstrdup: null input");
    }
    n = strlen(s);
    out = (char *)malloc(n + 1);
    if (!out) {
        die("out of memory in strdup");
    }
    memcpy(out, s, n + 1);
    return out;
}

static Rule *load_rules(const char *path, size_t *out_n_rules) {
    FILE *fp = fopen(path, "r");
    Rule *rules = NULL;
    size_t n_rules = 0;
    size_t cap = 0;
    char line[512];

    if (!fp) {
        fprintf(stderr, "error: failed to open rules file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *tok1;
        char *tok2;
        char *tok3;

        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        tok1 = strtok(line, " \t\r\n");
        if (!tok1) {
            continue;
        }
        tok2 = strtok(NULL, " \t\r\n");
        if (!tok2) {
            fprintf(stderr, "error: malformed rule line (missing value)\n");
            exit(1);
        }
        tok3 = strtok(NULL, " \t\r\n");
        if (!tok3) {
            fprintf(stderr, "error: malformed rule line (missing mnemonic)\n");
            exit(1);
        }

        if (n_rules == cap) {
            Rule *new_rules;
            cap = (cap == 0) ? 128 : cap * 2;
            new_rules = (Rule *)realloc(rules, cap * sizeof(*rules));
            if (!new_rules) {
                die("out of memory while growing rules array");
            }
            rules = new_rules;
        }

        rules[n_rules].mask = parse_u32_or_die(tok1);
        rules[n_rules].value = parse_u32_or_die(tok2);
        rules[n_rules].name = xstrdup_or_die(tok3);
        rules[n_rules].hits = 0;
        n_rules++;
    }

    if (ferror(fp)) {
        fprintf(stderr, "error: failed reading rules file '%s'\n", path);
        exit(1);
    }
    fclose(fp);

    if (n_rules == 0) {
        die("no decode rules loaded");
    }

    *out_n_rules = n_rules;
    return rules;
}

static void process_word(uint32_t insn, Rule *rules, size_t n_rules, Stats *stats) {
    size_t i;

    if (insn == 0u) {
        stats->skipped_zero_words++;
        return;
    }

    stats->total_words++;
    for (i = 0; i < n_rules; i++) {
        if ((insn & rules[i].mask) == rules[i].value) {
            stats->matched_words++;
            rules[i].hits++;
            return;
        }
    }

    stats->unmatched_words++;

    {
        unsigned idx11 = (unsigned)(insn >> 21);
        unsigned idx7 = (unsigned)(insn >> 25);

        stats->bucket11[idx11]++;
        stats->bucket7[idx7]++;
        if (!stats->has_example11[idx11]) {
            stats->has_example11[idx11] = true;
            stats->example11[idx11] = insn;
        }
        if (!stats->has_example7[idx7]) {
            stats->has_example7[idx7] = true;
            stats->example7[idx7] = insn;
        }
    }
}

static void process_binary_file(const char *path, Rule *rules, size_t n_rules, Stats *stats) {
    FILE *fp = fopen(path, "rb");
    uint8_t *buf = NULL;
    size_t cap = 1u << 20; /* 1 MiB */
    size_t carry = 0;

    if (!fp) {
        fprintf(stderr, "error: failed to open binary file '%s': %s\n", path, strerror(errno));
        exit(1);
    }

    buf = (uint8_t *)malloc(cap + 3);
    if (!buf) {
        die("out of memory allocating input buffer");
    }

    for (;;) {
        size_t n = fread(buf + carry, 1, cap, fp);
        size_t total = carry + n;
        size_t words = total / 4;
        size_t i;

        if (n == 0 && feof(fp)) {
            stats->trailing_bytes += carry;
            break;
        }
        if (n == 0 && ferror(fp)) {
            fprintf(stderr, "error: failed reading '%s'\n", path);
            exit(1);
        }

        for (i = 0; i < words; i++) {
            size_t off = i * 4;
            uint32_t insn = (uint32_t)buf[off] |
                            ((uint32_t)buf[off + 1] << 8) |
                            ((uint32_t)buf[off + 2] << 16) |
                            ((uint32_t)buf[off + 3] << 24);
            process_word(insn, rules, n_rules, stats);
        }

        carry = total - words * 4;
        if (carry > 0) {
            memmove(buf, buf + words * 4, carry);
        }
    }

    free(buf);
    fclose(fp);
    stats->files_processed++;
}

static int cmp_stat_desc(const void *a, const void *b) {
    const MnemonicStat *sa = (const MnemonicStat *)a;
    const MnemonicStat *sb = (const MnemonicStat *)b;
    if (sa->hits < sb->hits) {
        return 1;
    }
    if (sa->hits > sb->hits) {
        return -1;
    }
    return strcmp(sa->name, sb->name);
}

static void print_top_mnemonics(const Rule *rules, size_t n_rules, const Stats *stats, size_t topn) {
    MnemonicStat *agg = NULL;
    size_t agg_len = 0;
    size_t agg_cap = 0;
    size_t i;

    for (i = 0; i < n_rules; i++) {
        size_t j;
        bool found = false;
        if (rules[i].hits == 0) {
            continue;
        }
        for (j = 0; j < agg_len; j++) {
            if (strcmp(agg[j].name, rules[i].name) == 0) {
                agg[j].hits += rules[i].hits;
                found = true;
                break;
            }
        }
        if (found) {
            continue;
        }
        if (agg_len == agg_cap) {
            MnemonicStat *new_agg;
            agg_cap = (agg_cap == 0) ? 64 : agg_cap * 2;
            new_agg = (MnemonicStat *)realloc(agg, agg_cap * sizeof(*agg));
            if (!new_agg) {
                free(agg);
                die("out of memory while aggregating mnemonics");
            }
            agg = new_agg;
        }
        agg[agg_len].name = rules[i].name;
        agg[agg_len].hits = rules[i].hits;
        agg_len++;
    }

    if (agg_len == 0) {
        printf("Top matched mnemonics:\n");
        printf("  (none)\n");
        free(agg);
        return;
    }

    qsort(agg, agg_len, sizeof(*agg), cmp_stat_desc);
    if (topn > agg_len) {
        topn = agg_len;
    }

    printf("Top %zu matched mnemonics:\n", topn);
    for (i = 0; i < topn; i++) {
        double pct_total = (stats->total_words == 0)
                               ? 0.0
                               : (100.0 * (double)agg[i].hits / (double)stats->total_words);
        printf("%2zu. %-18s count=%" PRIu64 " (%.4f%% of words)\n",
               i + 1, agg[i].name, agg[i].hits, pct_total);
    }
    free(agg);
}

static void print_top_buckets11(const Stats *stats, size_t topn) {
    bool used[2048] = {0};
    size_t rank;

    printf("Top %zu unmatched prefixes (11 high bits):\n", topn);
    for (rank = 0; rank < topn; rank++) {
        size_t i;
        int best = -1;
        uint64_t best_count = 0;

        for (i = 0; i < 2048; i++) {
            if (!used[i] && stats->bucket11[i] > best_count) {
                best_count = stats->bucket11[i];
                best = (int)i;
            }
        }

        if (best < 0 || best_count == 0) {
            break;
        }
        used[best] = true;

        printf("%2zu. count=%" PRIu64 " mask=0x%08X value=0x%08X example=0x%08X\n",
               rank + 1,
               best_count,
               0xFFE00000u,
               (uint32_t)((uint32_t)best << 21),
               stats->has_example11[best] ? stats->example11[best] : 0u);
    }
}

static void print_top_buckets7(const Stats *stats, size_t topn) {
    bool used[128] = {0};
    size_t rank;

    printf("Top %zu unmatched prefixes (7 high bits):\n", topn);
    for (rank = 0; rank < topn; rank++) {
        size_t i;
        int best = -1;
        uint64_t best_count = 0;

        for (i = 0; i < 128; i++) {
            if (!used[i] && stats->bucket7[i] > best_count) {
                best_count = stats->bucket7[i];
                best = (int)i;
            }
        }

        if (best < 0 || best_count == 0) {
            break;
        }
        used[best] = true;

        printf("%2zu. count=%" PRIu64 " mask=0x%08X value=0x%08X example=0x%08X\n",
               rank + 1,
               best_count,
               0xFE000000u,
               (uint32_t)((uint32_t)best << 25),
               stats->has_example7[best] ? stats->example7[best] : 0u);
    }
}

int main(int argc, char **argv) {
    const char *rules_path;
    Rule *rules;
    size_t n_rules;
    Stats stats;
    size_t i;
    double coverage;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <named_rules.txt> <binary-file> [binary-file...]\n", argv[0]);
        return 1;
    }

    rules_path = argv[1];
    rules = load_rules(rules_path, &n_rules);
    memset(&stats, 0, sizeof(stats));

    for (i = 2; i < (size_t)argc; i++) {
        process_binary_file(argv[i], rules, n_rules, &stats);
    }

    coverage = (stats.total_words == 0) ? 0.0 : (100.0 * (double)stats.matched_words / (double)stats.total_words);

    printf("rules=%zu\n", n_rules);
    printf("files=%" PRIu64 "\n", stats.files_processed);
    printf("total_words=%" PRIu64 "\n", stats.total_words);
    printf("skipped_zero_words=%" PRIu64 "\n", stats.skipped_zero_words);
    printf("matched_words=%" PRIu64 "\n", stats.matched_words);
    printf("unmatched_words=%" PRIu64 "\n", stats.unmatched_words);
    printf("coverage=%.4f%%\n", coverage);
    printf("trailing_bytes_ignored=%" PRIu64 "\n", stats.trailing_bytes);
    print_top_mnemonics(rules, n_rules, &stats, 30);
    print_top_buckets11(&stats, 20);
    print_top_buckets7(&stats, 12);

    for (i = 0; i < n_rules; i++) {
        free(rules[i].name);
    }
    free(rules);
    return 0;
}
