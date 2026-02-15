CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
LDLIBS ?= -lm
KSHOT_APK_PATH ?= /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk
KSHOT_PROFILE_MODE ?= relaxed

.PHONY: all clean run-example run-branch-example run-movk-example run-addreg-example run-reg8-addimm-example run-reg9-memory-example run-reg10-addreg-example run-spill-addimm-example run-spill-movk-example run-spill-addreg-example run-spill-csel-eq-example run-spill-csel-ne-example run-spill-cbz-example run-spill-tbz-example run-spill-memory64-example run-spill-memory32-example run-spill-ldur64-example run-spill-byte-example run-spill-ldrsb-example run-spill-memory-oob-example run-spill-postpre64-example run-spill-postpre32-example run-spill-postpre-ldrsb-example run-spill-pair-postpre64-example run-spill-pair-offset64-example run-memory-example run-memory32-example run-oob-example run-cond-eq-example run-cond-lt-example run-csel-true-example run-csel-false-example run-ands-example run-tst-example run-shift-add-lsl-example run-shift-sub-lsr-example run-shift-cmp-asr-example run-orr-shift-example run-eor-shift-example run-bics-example run-bcond-crossblock-example run-flags-preserve-add-example run-tbz-example run-tbnz-example run-bl-ret-example run-adr-example run-adrp-example run-ldur-example run-ldur32-example run-ldursw-example run-ldur-neg-example run-ldur-neg-oob-example run-ldp-example run-ldp32-example run-ldrb-example run-ldrh-example run-ldrsb-example run-ldrsh-example run-ldurb-example run-ldurh-example run-ldursb-example run-ldursh-example run-ldurb-neg-example run-ldurh-neg-example run-ldurb-neg-oob-example run-ldurh-neg-oob-example run-postidx-str64-example run-preidx-ldr64-example run-postidx-str32-example run-preidx-ldr32-example run-postidx-strb-example run-preidx-ldrb-example run-postidx-strh-example run-preidx-ldrh-example run-postidx-ldrsb-example run-postidx-ldrsh-example run-postidx-ldrsw-example run-pair-post-store-pre-load64-example run-pair-pre-store-post-load64-example run-pair-post-store-pre-load32-example run-pair-pre-store-post-load32-example run-ldxr-stxr64-example run-stxr64-fail-example run-ldxr-stxr32-example run-ldxrb-stxrb-example run-stxrb-fail-example run-ldaxrb-stlxrb-example run-stlxrb-fail-example run-ldxrh-stxrh-example run-stxrh-fail-example run-ldaxr-stlxr64-example run-stlxr64-fail-example run-ldar-stlr64-example run-ldar-stlr32-example run-swp64-example run-ldadd64-example run-ldclr64-example run-ldeor64-example run-ldset64-example run-ldaddb-wrap-example run-ldsmax32-sign-example run-ldsmin32-sign-example run-ldumax32-example run-ldumin32-example run-ldsmaxb-al-example run-ldsminh-a-example run-ldumax64-l-example run-lduminb-al-example run-stadd64-alias-example run-stclrh-alias-example run-steorb-alias-example run-stset32-alias-example run-swp64-alias-example run-ldadd64-oob-example run-cas64-success-example run-cas64-fail-example run-cas32-rtx0-example run-casb-success-example run-caslb-fail-example run-casah-success-example run-casa64-success-example run-casl64-fail-example run-casal32-rtx0-example run-casp64-success-example run-casp64-fail-example run-caspal64-success-example run-caspa32-success-example run-cas64-rszr-success-example run-cas64-rszr-fail-example run-cas64-rtzr-success-example run-cas64-rszr-oob-example run-casb-rszr-success-example run-caslb-rszr-fail-example run-casah-rtzr-success-example run-casal32-rtzr-success-example run-cas32-rszr-success-example run-casah-rszr-oob-example run-spill-ldxr-stxr64-example run-spill-stxr64-fail-example run-spill-ldaxr-stlxr64-example run-spill-stlxr64-fail-example run-spill-ldar-stlr64-example run-spill-ldar-stlr32-example run-spill-swp64-example run-spill-ldadd64-example run-spill-cas64-success-example run-spill-cas64-fail-example run-spill-casp64-success-example run-spill-casp64-fail-example stress-spill-atomics
.PHONY: run-ret-x1-example run-ret-midblock-example run-ret-xzr-example run-br-example run-br-midblock-example run-br-xzr-example run-blr-ret-example run-blr-xzr-example run-bl-ret-nested-example run-lr-overflow-example run-dispatch-version-miss-example run-dispatch-version-miss-midblock-example run-dispatch-slot-invalidate-midblock-example run-dispatch-slot-invalidate-all-example run-dispatch-version-miss-cli-example run-dispatch-slot-invalidate-cli-example run-debug-exit-example runtime-api-demo run-runtime-api-demo
.PHONY: run-code-file-example run-code-file-pc-example run-set-reg-example run-trace-state-example run-sp-addsub-imm-example run-sp-prologue-epilogue-example run-sp-ldrstr-imm-example run-sp-ldurstur-example run-sp-postpre-single-example run-mem-write-read-example run-mem-write-file-example run-mem-read-file-example
.PHONY: opcode_inventory_tool run-opcode-inventory mnemonic_inventory_tool run-mnemonic-inventory
.PHONY: run-movk32-example run-movn-example run-movn32-example run-movn32-shift-example run-movn64-shift-example run-movz64-xzr-discard-example run-movn64-xzr-discard-example run-movk64-xzr-discard-example run-movz32-wzr-discard-example run-movn32-wzr-discard-example run-movk32-wzr-discard-example run-addimm32-example run-addimm32-wsp-source-example run-addimm32-wsp-dst-example run-subimm32-wsp-source-example run-subimm32-wsp-dst-example run-cmpimm32-example
.PHONY: run-addreg32-example run-subreg32-example run-andreg64-example run-bicreg64-example run-andreg32-example run-bicreg32-example run-andreg-flags-preserve-example run-addsreg64-example run-subsreg64-example run-addsreg32-example run-subsreg32-example run-cmnreg64-eq-example run-cmpreg64-eqfalse-example run-addext64-uxtw-example run-subext64-sxtw-example run-addext32-uxtb-example run-subext32-sxth-example run-addext64-sp-source-example run-subext64-sp-source-example run-addext64-sp-dst-example run-subext64-sp-dst-example run-addext64-sp-flags-preserve-example run-addext32-sp-source-example run-subext32-sp-source-example run-addext32-sp-dst-example run-subext32-sp-dst-example run-addsext64-uxtw-example run-subsext64-sxtw-example run-addsext32-uxtb-example run-subsext32-sxth-example run-addsext64-zr-source-example run-subsext64-zr-source-example run-addsext32-zr-source-example run-subsext32-zr-source-example run-cmnext64-zr-eq-example run-cmpext64-zr-eq-example run-cmnext32-zr-eq-example run-cmpext32-zr-eq-example run-cmnext64-eq-example run-cmpext64-eqfalse-example run-orrreg32-example run-ornreg32-example run-mvn32-alias-example run-eorreg32-example run-andsreg32-example run-bicsreg32-example run-cmpreg32-example run-ccmpreg64-true-example run-ccmpreg64-false-nzcv-example run-ccmpimm64-true-example run-ccmpimm32-false-nzcv-example run-ccmpreg32-true-example run-ccmnreg64-true-example run-ccmnreg64-false-nzcv-example run-ccmnimm32-true-example run-ccmnimm64-false-nzcv-example run-fcmpd-lt-example run-fcmpd-imm0-eq-example run-fcmpe-d-unordered-example run-fadds-example run-faddd-example run-fsubs-example run-fsubd-example run-fmuls-example run-fmuld-example run-fdivd-example run-fmov-ws-roundtrip-example run-fmov-xd-roundtrip-example run-scvtf-fcvtzs64-example run-ucvtf-fcvtzu64-example run-fccmpd-true-lt-example run-fccmps-false-nzcv-example run-fccmpd-unordered-example run-fccmped-unordered-example run-shift32-lsr-example run-addreg64-zr-source-example run-subreg64-zr-source-example run-addreg32-zr-source-example run-subreg32-zr-source-example run-addreg64-sp-source-example run-subreg64-sp-source-example run-addreg64-sp-dst-example run-subreg64-sp-dst-example run-addreg64-sp-flags-preserve-example run-addreg32-sp-source-example run-subreg32-sp-source-example run-addreg32-sp-dst-example run-subreg32-sp-dst-example run-orrreg64-zr-alias-example run-ornreg64-example run-mvn64-alias-example run-orrreg32-zr-alias-example run-eorreg64-zr-source-example run-andsreg64-zr-source-example run-bicsreg64-zr-source-example run-cmpreg64-zr-source-example run-orrreg64-zr-discard-flags-example
.PHONY: run-andimm32-example run-orrimm32-example run-eorimm32-example run-tstimm32-example run-orrimm64-example
.PHONY: run-ubfm32-lsr-example run-ubfm32-lsl-example run-ubfm64-lsr-example
.PHONY: run-addsimm32-example run-subsimm32-example run-cmnimm32-example run-addsimm64-example run-subsimm64-example run-cmpimm64-sp-eq-example run-cmpimm32-wsp-eq-example run-addsimm64-sp-source-example run-subsimm64-sp-source-example run-addsimm32-wsp-source-example run-subsimm32-wsp-source-example run-cmnimm64-sp-eq-example run-cmnimm32-wsp-eq-example
.PHONY: run-hint-bti-example
.PHONY: run-mrs-tpidr-el0-example
.PHONY: run-csel32-true-example run-csel32-false-example run-csel64-rn-zr-true-example run-csel64-rm-zr-false-example run-csel64-rd-zr-discard-example run-csel32-rn-zr-true-example run-csel32-rm-zr-false-example run-csel32-rd-zr-discard-example run-csinc32-false-example run-csinv64-false-example run-csneg64-false-example run-cset32-eq-example run-cset64-eq-example run-csetm32-eq-example run-csetm64-eq-example
.PHONY: run-udiv64-example run-sdiv64-example run-udiv32-example run-sdiv32-example run-udiv64-divzero-example run-sdiv64-overflow-example run-sdiv32-overflow-example
.PHONY: run-umaddl-example run-umull-example run-umsubll-example run-smull-example run-smsubll-example
.PHONY: run-madd64-example run-mul64-example run-msub64-example run-madd32-example run-mul32-example run-msub32-example
.PHONY: run-lslv64-example run-lsrv64-example run-asrv64-example run-rorv64-example run-lslv32-example run-lsrv32-example run-asrv32-example run-rorv32-example run-extr64-example run-extr32-example run-ror64-imm-example run-ror32-imm-example
.PHONY: run-sbfm32-asr-example run-sbfm64-asr-example run-bfm64-lowbyte-example run-bfm64-insert-byte-example run-bfm32-lowbyte-example run-bfm32-insert-byte-example
.PHONY: run-regoff32-uxtw-example run-regoff32-lsl-example run-regoff32-sxtw-neg-example run-regoff64-uxtw-example run-regoff64-lsl-example run-regoff64-sxtw-neg-example run-regoff8-uxth-example run-regoff8-lsl-example run-regoff8-sxtw-neg-example run-regoff8-alt-example run-regoff16-uxth-example run-regoff16-lsl-example run-regoff16-sxtw-neg-example run-regoff16-alt-example
.PHONY: run-ldrstrq-example run-ldurq-example run-postidx-strq-example run-preidx-ldrq-example run-postidx-strd-example run-preidx-ldrd-example run-postidx-strs-example run-preidx-ldrs-example run-sturldur-d-unscaled-example run-sturldur-s-unscaled-example run-ldpstpq-example run-stpldpq-postpre-example run-neon-and16b-example run-neon-bic16b-example run-neon-orr16b-example run-neon-eor16b-example run-neon-eor8b-zero-upper-example run-neon-movi16b-example run-neon-movi8b-example run-neon-movi8b-zero-upper-example run-neon-movi2d-zero-example run-neon-movi2d-ones-example run-neon-sqrdmlah2s-example run-neon-sqrdmlah4s-example run-neon-sqrdmlsh2s-example run-neon-sqrdmlsh4s-example
.PHONY: run-strxzr-imm-example run-strwzr-imm-example run-ldrxzr-imm-discard-example run-ldrwzr-imm-discard-example run-sturxzr-example run-sturwzr-example run-postidx-str64-xzr-source-example run-postidx-str32-wzr-source-example run-regoff64-str-xzr-source-example run-regoff32-str-wzr-source-example
.PHONY: run-stp64-zr-source-offset-example run-stp32-zr-source-offset-example run-ldp64-zr-discard-offset-example run-ldp32-zr-discard-offset-example run-stp64-zr-source-postpre-example run-stp32-zr-source-postpre-example
.PHONY: run-cbz32-example run-cbnz32-example run-cbz32-wzr-example run-cbnz32-wzr-example
.PHONY: run-tbz32-wzr-example run-tbnz32-wzr-example run-tbz64-bit32-example run-tbnz64-bit32-example run-adr-xzr-discard-example run-adrp-xzr-discard-example run-adr-spill-rd-example run-adrp-spill-rd-example
.PHONY: run-ldxr64-xzr-monitor-example run-ldxr32-wzr-monitor-example run-ldaxr64-xzr-monitor-example run-ldar64-xzr-discard-example run-ldar32-wzr-discard-example run-ldxr-stxr64-sp-base-example run-ldaxr-stlxr64-sp-base-example
.PHONY: run-stlr64-xzr-zero-store-example run-stlr32-wzr-zero-store-example run-stlrb-wzr-zero-store-example run-stlrh-wzr-zero-store-example run-ldar-stlr64-sp-base-example run-ldar-stlr32-sp-base-example
.PHONY: run-stxr64-xzr-zero-store-example run-stxr32-wzr-zero-store-example run-stxrb-wzr-zero-store-example run-stxrh-wzr-zero-store-example run-stlxr64-xzr-zero-store-example run-stlxrb-wzr-zero-store-example
.PHONY: run-stxr64-wszr-status-discard-example run-stlxr64-wszr-status-discard-example run-stxr64-wszr-fail-discard-example run-stlxr64-wszr-fail-discard-example
.PHONY: run-swp64-sp-base-example run-ldadd64-sp-base-example run-cas64-success-sp-base-example run-cas64-fail-sp-base-example run-casp64-success-sp-base-example run-casp64-fail-sp-base-example
.PHONY: run-spill-ldxr-stxr64-sp-base-example run-spill-stxr64-fail-sp-base-example run-spill-ldaxr-stlxr64-sp-base-example run-spill-stlxr64-fail-sp-base-example run-spill-ldar-stlr64-sp-base-example run-spill-ldar-stlr32-sp-base-example run-spill-swp64-sp-base-example run-spill-ldadd64-sp-base-example run-spill-cas64-success-sp-base-example run-spill-cas64-fail-sp-base-example run-spill-casp64-success-sp-base-example run-spill-casp64-fail-sp-base-example
.PHONY: run-spill-casa64-success-sp-base-example run-spill-casl64-fail-sp-base-example run-spill-casal32-rtx0-sp-base-example run-spill-casb-success-sp-base-example run-spill-caslb-fail-sp-base-example run-spill-casah-success-sp-base-example
.PHONY: run-unsupported-log-example run-unsupported-unreached-example run-elf-symbol-example run-elf-branch-trampoline-example run-elf-import-stub-example run-elf-import-callback-example run-elf-import-trace-example run-elf-import-preset-example run-import-callback-retx1-example run-import-callback-add-example run-import-callback-sp-example run-import-callback-alloc-example run-import-callback-free-example run-import-callback-alloc-free-example run-import-callback-calloc-example run-import-callback-calloc-zero-example run-import-callback-realloc-example run-import-callback-realloc-null-example run-import-callback-memcpy-example run-import-callback-memset-example run-import-callback-memcmp-eq-example run-import-callback-memcmp-ne-example run-import-callback-memmove-example run-import-callback-strnlen-example run-import-callback-strnlen-max-example run-import-callback-strlen-example run-import-callback-strcmp-eq-example run-import-callback-strcmp-ne-example run-import-callback-strncmp-eq-prefix-example run-import-callback-strncmp-ne-example run-import-callback-strcpy-example run-import-callback-strncpy-pad-example run-import-callback-strchr-hit-example run-import-callback-strchr-miss-example run-import-callback-strchr-nul-example run-import-callback-strrchr-hit-example run-import-callback-strrchr-miss-example run-import-callback-strstr-hit-example run-import-callback-strstr-miss-example run-import-callback-strstr-empty-needle-example run-import-callback-memchr-hit-example run-import-callback-memchr-miss-example run-import-callback-memchr-limit-example run-import-callback-memrchr-hit-example run-import-callback-memrchr-miss-example run-import-callback-atoi-example run-import-callback-atoi-neg-example run-import-callback-strtol-base0-example run-import-callback-strtol-base16-example run-import-callback-strtol-invalid-base-example run-import-callback-retneg1-example run-import-callback-strtoul-example run-import-callback-posix-memalign-example run-import-callback-posix-memalign-einval-example run-import-callback-basename-example run-import-callback-strdup-example run-import-callback-strtof-example run-import-callback-snprintf-mixed-example run-import-callback-snprintf-trunc-example run-import-callback-snprintf-widthprec-example run-import-callback-snprintf-starwidth-example run-import-callback-snprintf-float-n-example run-import-callback-snprintf-stack-varargs-example run-import-callback-vsnprintf-example run-import-callback-vsnprintf-chk-example run-import-callback-vfprintf-example run-import-callback-vasprintf-example run-import-callback-vsscanf-example run-import-callback-snprintf-inf-example run-import-callback-snprintf-trunc-edge-example run-import-callback-strtod-example run-import-callback-strtod-nan-example run-import-callback-sscanf-example run-import-callback-sscanf-float-n-scanset-example run-import-callback-sscanf-stack-varargs-example run-import-callback-sscanf-scanset-invert-example run-kingshot-import-profile run-kingshot-import-profile-all run-kingshot-smoke run-kingshot-smoke-matrix run-nativebridge-skeleton-build run-nativebridge-skeleton-demo
.PHONY: run-kingshot-import-profile-strict run-kingshot-import-profile-all-strict run-kingshot-coverage-gate verify-kingshot run-nativebridge-skeleton-jni-probe run-kingshot-smoke-matrix-ci
.PHONY: run-kingshot-import-profile-compat run-kingshot-import-profile-all-compat verify-kingshot-ci
.PHONY: run-import-callback-pow-example run-import-callback-sqrt-example run-import-callback-cos-example run-import-callback-tan-example run-import-callback-exp-example run-import-callback-log-example run-import-callback-log10-example run-import-callback-floor-example run-import-callback-ceil-example run-import-callback-trunc-example run-import-callback-fmod-example run-import-callback-sin-example run-import-callback-sinh-example run-import-callback-tanh-example run-import-callback-sinf-example run-import-callback-sincosf-example run-import-callback-exp2f-example run-import-callback-log2f-example run-import-callback-log10f-example run-import-callback-lround-example
.PHONY: run-import-callback-islower-example run-import-callback-isspace-example run-import-callback-isxdigit-example run-import-callback-isupper-example run-import-callback-toupper-example run-import-callback-tolower-example
.PHONY: run-import-callback-retneg1-enosys-example run-import-callback-retneg1-eagain-example run-import-callback-retneg1-eintr-example run-import-callback-retneg1-eacces-example run-import-callback-retneg1-enoent-example run-import-callback-retneg1-eperm-example run-import-callback-retneg1-etimedout-example run-import-callback-errno-slot-example run-import-callback-handle-example run-import-callback-ctime-example run-import-callback-gmtime-example run-import-callback-daylight-example run-import-callback-timezone-example

all: tiny_dbt

tiny_dbt: tiny_dbt.c tiny_dbt_runtime.o tiny_dbt_runtime.h
	$(CC) $(CFLAGS) -o $@ tiny_dbt.c tiny_dbt_runtime.o $(LDLIBS)

tiny_dbt_runtime.o: tiny_dbt_runtime.c tiny_dbt_runtime.h tiny_dbt_runtime_emit.inc.c tiny_dbt_runtime_helpers.inc.c tiny_dbt_runtime_decode.inc.c tiny_dbt_runtime_api.inc.c
	$(CC) $(CFLAGS) -DTINY_DBT_NO_MAIN -c -o $@ tiny_dbt_runtime.c

runtime_api_demo: runtime_api_demo.c tiny_dbt_runtime.o tiny_dbt_runtime.h
	$(CC) $(CFLAGS) -o $@ runtime_api_demo.c tiny_dbt_runtime.o $(LDLIBS)

opcode_inventory_tool: scripts/opcode_inventory.c
	$(CC) $(CFLAGS) -O3 -o scripts/opcode_inventory_tool scripts/opcode_inventory.c

mnemonic_inventory_tool: scripts/mnemonic_inventory.c
	$(CC) $(CFLAGS) -O3 -o scripts/mnemonic_inventory_tool scripts/mnemonic_inventory.c

run-runtime-api-demo: runtime_api_demo
	./runtime_api_demo

run-opcode-inventory: opcode_inventory_tool
	./scripts/run_opcode_inventory.sh

run-mnemonic-inventory: mnemonic_inventory_tool
	./scripts/run_mnemonic_inventory.sh

run-example: tiny_dbt
	./tiny_dbt D28000E0 91008C00 D65F03C0

run-hint-bti-example: tiny_dbt
	./tiny_dbt D2800540 D503245F D503201F D65F03C0

run-mrs-tpidr-el0-example: tiny_dbt
	./tiny_dbt D28000A0 D53BD048 91000100 D65F03C0

run-code-file-example: tiny_dbt
	@tmp=/tmp/tiny_dbt_code_file_example.bin; \
	printf '\340\000\200\322\000\214\000\221\300\003\137\326' > $$tmp; \
	./tiny_dbt --code-file $$tmp

run-code-file-pc-example: tiny_dbt
	@tmp=/tmp/tiny_dbt_code_file_pc_example.bin; \
	printf '\300\003\137\326\100\005\200\322\300\003\137\326' > $$tmp; \
	./tiny_dbt --pc-bytes 4 --code-file $$tmp

run-set-reg-example: tiny_dbt
	./tiny_dbt --set-reg x0=1337 D65F03C0

run-trace-state-example: tiny_dbt
	./tiny_dbt --trace-state D28000E0 91008C00 D65F03C0

run-sp-addsub-imm-example: tiny_dbt
	./tiny_dbt D2800801 9100003F D10043FF 910043FF 910003E0 D65F03C0

run-sp-prologue-epilogue-example: tiny_dbt
	./tiny_dbt D2800801 9100003F D28000B3 D28000F4 A9BF53F3 D2800013 D2800014 A8C153F3 8B140260 D65F03C0

run-sp-ldrstr-imm-example: tiny_dbt
	./tiny_dbt D2800401 9100003F D2800540 F90003E0 D2800000 F94003E0 D65F03C0

run-sp-ldurstur-example: tiny_dbt
	./tiny_dbt D2800401 9100003F D2800540 F80083E0 D2800000 F84083E0 D65F03C0

run-sp-postpre-single-example: tiny_dbt
	./tiny_dbt D2800401 9100003F D2800540 F80087E0 D2800000 F85F8FE0 910003E1 8B010000 D65F03C0

run-mem-write-read-example: tiny_dbt
	./tiny_dbt --mem-write 0x20:8877665544332211 --mem-read 0x20:8 D2800401 F9400020 D65F03C0

run-mem-write-file-example: tiny_dbt
	@tmp=/tmp/tiny_dbt_mem_blob.bin; \
	printf '\210\167\146\125\104\063\042\021' > $$tmp; \
	./tiny_dbt --mem-write-file 0x20:$$tmp --mem-read 0x20:8 D2800401 F9400020 D65F03C0

run-mem-read-file-example: tiny_dbt
	@tmp=/tmp/tiny_dbt_mem_dump.bin; \
	./tiny_dbt --mem-write 0x20:8877665544332211 --mem-read-file 0x20:8:$$tmp D2800401 F9400020 D65F03C0; \
	od -An -tx1 -v $$tmp

run-branch-example: tiny_dbt
	./tiny_dbt D2800020 B4000040 9100A400 D65F03C0

run-movk-example: tiny_dbt
	./tiny_dbt D28ACF00 F2A24680 D65F03C0

run-movk32-example: tiny_dbt
	./tiny_dbt 528ACF00 72A24680 D65F03C0

run-movn-example: tiny_dbt
	./tiny_dbt 92800000 D65F03C0

run-movn32-example: tiny_dbt
	./tiny_dbt 12800000 D65F03C0

run-movn32-shift-example: tiny_dbt
	./tiny_dbt 12A24680 D65F03C0

run-movn64-shift-example: tiny_dbt
	./tiny_dbt 92D579A0 D65F03C0

run-movz64-xzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 D28ACF1F D65F03C0

run-movn64-xzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 9280001F D65F03C0

run-movk64-xzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 F2A2469F D65F03C0

run-movz32-wzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 528ACF1F D65F03C0

run-movn32-wzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 1280001F D65F03C0

run-movk32-wzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 72A2469F D65F03C0

run-addreg-example: tiny_dbt
	./tiny_dbt D2800C80 D28000A1 8B010000 D65F03C0

run-addimm32-example: tiny_dbt
	./tiny_dbt 528000E0 11008C00 D65F03C0

run-addimm32-wsp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x1000000FF 110007E0 D65F03C0

run-addimm32-wsp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x1000000FF 110007FF 910003E0 D65F03C0

run-subimm32-wsp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000100 510007E0 D65F03C0

run-subimm32-wsp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000100 510007FF 910003E0 D65F03C0

run-cmpimm32-example: tiny_dbt
	./tiny_dbt 528000A0 7100141F 54000040 52800000 D65F03C0

run-addsimm32-example: tiny_dbt
	./tiny_dbt 528004A0 31001400 D65F03C0

run-subsimm32-example: tiny_dbt
	./tiny_dbt 528005E0 71001400 D65F03C0

run-cmnimm32-example: tiny_dbt
	./tiny_dbt 52800500 3100081F 54000041 52800000 D65F03C0

run-addsimm64-example: tiny_dbt
	./tiny_dbt D2800500 B1000800 D65F03C0

run-subsimm64-example: tiny_dbt
	./tiny_dbt D28005A0 F1000C00 D65F03C0

run-cmpimm64-sp-eq-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 F10403FF 9A9F17E0 D65F03C0

run-cmpimm32-wsp-eq-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x1000000FF 7103FFFF 1A9F17E0 D65F03C0

run-addsimm64-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 B10017E0 D65F03C0

run-subsimm64-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 F10017E0 D65F03C0

run-addsimm32-wsp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x1000000FF 310017E0 D65F03C0

run-subsimm32-wsp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000100 710017E0 D65F03C0

run-cmnimm64-sp-eq-example: tiny_dbt
	./tiny_dbt --set-reg sp=0 B10003FF 9A9F17E0 D65F03C0

run-cmnimm32-wsp-eq-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000000 310003FF 1A9F17E0 D65F03C0

run-udiv64-example: tiny_dbt
	./tiny_dbt D2800A80 D2800041 9AC10800 D65F03C0

run-sdiv64-example: tiny_dbt
	./tiny_dbt D2800A80 D2800041 9AC10C00 D65F03C0

run-udiv32-example: tiny_dbt
	./tiny_dbt 52800A80 52800041 1AC10800 D65F03C0

run-sdiv32-example: tiny_dbt
	./tiny_dbt 52800A80 52800041 1AC10C00 D65F03C0

run-udiv64-divzero-example: tiny_dbt
	./tiny_dbt D2800A80 D2800001 9AC10800 D65F03C0

run-sdiv64-overflow-example: tiny_dbt
	./tiny_dbt D2F00000 D2800001 D1000421 9AC10C00 D65F03C0

run-sdiv32-overflow-example: tiny_dbt
	./tiny_dbt 52B00000 52800001 51000421 1AC10C00 D65F03C0

run-umaddl-example: tiny_dbt
	./tiny_dbt D2800143 52800081 52800102 9BA20C20 D65F03C0

run-umull-example: tiny_dbt
	./tiny_dbt 528000C1 528000E2 9BA27C20 D65F03C0

run-umsubll-example: tiny_dbt
	./tiny_dbt D2800643 52800041 52800082 9BA28C20 D65F03C0

run-smull-example: tiny_dbt
	./tiny_dbt 52800001 51001821 528000E2 9B227C20 D65F03C0

run-smsubll-example: tiny_dbt
	./tiny_dbt D2800C83 52800041 528003A2 9B228C20 D65F03C0

run-madd64-example: tiny_dbt
	./tiny_dbt D2800143 D2800081 D2800102 9B020C20 D65F03C0

run-mul64-example: tiny_dbt
	./tiny_dbt D28000C1 D28000E2 9B027C20 D65F03C0

run-msub64-example: tiny_dbt
	./tiny_dbt D2800643 D2800041 D2800082 9B028C20 D65F03C0

run-madd32-example: tiny_dbt
	./tiny_dbt 52800143 52800081 52800102 1B020C20 D65F03C0

run-mul32-example: tiny_dbt
	./tiny_dbt 528000C1 528000E2 1B027C20 D65F03C0

run-msub32-example: tiny_dbt
	./tiny_dbt 52800643 52800041 52800082 1B028C20 D65F03C0

run-lslv64-example: tiny_dbt
	./tiny_dbt D28002A0 D2800021 9AC12000 D65F03C0

run-lsrv64-example: tiny_dbt
	./tiny_dbt D2800A80 D2800021 9AC12400 D65F03C0

run-asrv64-example: tiny_dbt
	./tiny_dbt D2800000 D1015000 D2800021 9AC12800 D65F03C0

run-rorv64-example: tiny_dbt
	./tiny_dbt D2800AA0 D2800021 9AC12C00 D65F03C0

run-lslv32-example: tiny_dbt
	./tiny_dbt 528002A0 52800021 1AC12000 D65F03C0

run-lsrv32-example: tiny_dbt
	./tiny_dbt 52800A80 52800021 1AC12400 D65F03C0

run-asrv32-example: tiny_dbt
	./tiny_dbt 52800000 51015000 52800021 1AC12800 D65F03C0

run-rorv32-example: tiny_dbt
	./tiny_dbt 52800AA0 52800021 1AC12C00 D65F03C0

run-extr64-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:EFCDAB89674523011032547698BADCFE D2800003 F9400061 F9400462 93C22020 D65F03C0

run-extr32-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:7856341221436587 D2800003 B9400061 B9400462 13822020 D65F03C0

run-ror64-imm-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:EFCDAB8967452301 D2800003 F9400061 93C12020 D65F03C0

run-ror32-imm-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:78563412 D2800003 B9400061 13812020 D65F03C0

run-sbfm32-asr-example: tiny_dbt
	./tiny_dbt 52800000 51015000 13017C00 D65F03C0

run-sbfm64-asr-example: tiny_dbt
	./tiny_dbt D2800000 D1015000 9341FC00 D65F03C0

run-bfm64-lowbyte-example: tiny_dbt
	./tiny_dbt D2824000 D2800541 B3401C20 D65F03C0

run-bfm64-insert-byte-example: tiny_dbt
	./tiny_dbt D2824000 D2800541 B3781C20 D65F03C0

run-bfm32-lowbyte-example: tiny_dbt
	./tiny_dbt 52824000 52800541 33001C20 D65F03C0

run-bfm32-insert-byte-example: tiny_dbt
	./tiny_dbt 52824000 52800541 33181C20 D65F03C0

run-andimm32-example: tiny_dbt
	./tiny_dbt 52824680 12001C00 D65F03C0

run-orrimm32-example: tiny_dbt
	./tiny_dbt 32003FE0 D65F03C0

run-eorimm32-example: tiny_dbt
	./tiny_dbt 52801E00 52001C00 D65F03C0

run-tstimm32-example: tiny_dbt
	./tiny_dbt 52802000 52800DE1 52801BC2 72001C1F 9A820020 D65F03C0

run-orrimm64-example: tiny_dbt
	./tiny_dbt B2401FE0 D65F03C0

run-ubfm32-lsr-example: tiny_dbt
	./tiny_dbt 52824680 53087C00 D65F03C0

run-ubfm32-lsl-example: tiny_dbt
	./tiny_dbt 52800240 53185C00 D65F03C0

run-ubfm64-lsr-example: tiny_dbt
	./tiny_dbt D28ACF00 F2A24680 D348FC00 D65F03C0

run-addreg32-example: tiny_dbt
	./tiny_dbt 52800500 52800041 0B010000 D65F03C0

run-subreg32-example: tiny_dbt
	./tiny_dbt 52800580 52800041 4B010000 D65F03C0

run-addreg64-zr-source-example: tiny_dbt
	./tiny_dbt D2800541 8B1F0020 D65F03C0

run-subreg64-zr-source-example: tiny_dbt
	./tiny_dbt D2800541 CB1F0020 D65F03C0

run-addreg32-zr-source-example: tiny_dbt
	./tiny_dbt 52800541 0B1F0020 D65F03C0

run-subreg32-zr-source-example: tiny_dbt
	./tiny_dbt 52800541 4B1F0020 D65F03C0

run-addreg64-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D2800541 8B0103E0 D65F03C0

run-subreg64-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D2800541 CB0103E0 D65F03C0

run-addreg64-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D2800541 8B0103FF 910003E0 D65F03C0

run-subreg64-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D2800541 CB0103FF 910003E0 D65F03C0

run-addreg64-sp-flags-preserve-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D28000A0 F100141F D2800541 8B0103FF 9A9F17E0 D65F03C0

run-addreg32-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000000 52800541 0B0103E0 D65F03C0

run-subreg32-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x10000002A 52800541 4B0103E0 D65F03C0

run-addreg32-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000000 52800541 0B0103FF 910003E0 D65F03C0

run-subreg32-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x10000002A 52800541 4B0103FF 910003E0 D65F03C0

run-andreg64-example: tiny_dbt
	./tiny_dbt D2800781 D28001E2 8A020020 D65F03C0

run-bicreg64-example: tiny_dbt
	./tiny_dbt D28007E1 D28001E2 8A220020 D65F03C0

run-andreg32-example: tiny_dbt
	./tiny_dbt 528007E1 528001E2 0A020020 D65F03C0

run-bicreg32-example: tiny_dbt
	./tiny_dbt 528007E1 528001E2 0A220020 D65F03C0

run-andreg-flags-preserve-example: tiny_dbt
	./tiny_dbt D28000A0 F100141F D2800061 D28000E2 8A020020 9A9F17E0 D65F03C0

run-addsreg64-example: tiny_dbt
	./tiny_dbt D28000A1 D28001A2 AB020020 D65F03C0

run-subsreg64-example: tiny_dbt
	./tiny_dbt D2800121 D28000A2 EB020020 D65F03C0

run-addsreg32-example: tiny_dbt
	./tiny_dbt 528000A1 528001A2 2B020020 D65F03C0

run-subsreg32-example: tiny_dbt
	./tiny_dbt 52800121 528000A2 6B020020 D65F03C0

run-cmnreg64-eq-example: tiny_dbt
	./tiny_dbt 92800001 D2800022 AB02003F 9A9F17E0 D65F03C0

run-cmpreg64-eqfalse-example: tiny_dbt
	./tiny_dbt D2800121 D28000A2 EB02003F 9A9F17E0 D65F03C0

run-addext64-uxtw-example: tiny_dbt
	./tiny_dbt D28000A1 D28000E2 8B224C20 D65F03C0

run-subext64-sxtw-example: tiny_dbt
	./tiny_dbt D2800C81 92800002 CB22C820 D65F03C0

run-addext32-uxtb-example: tiny_dbt
	./tiny_dbt 52800021 52802462 0B220020 D65F03C0

run-subext32-sxth-example: tiny_dbt
	./tiny_dbt 52807D01 12800002 4B22A420 D65F03C0

run-addext64-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D28000E2 8B224FE0 D65F03C0

run-subext64-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 92800002 CB22CBE0 D65F03C0

run-addext64-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D28000E2 8B224FFF 910003E0 D65F03C0

run-subext64-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 92800002 CB22CBFF 910003E0 D65F03C0

run-addext64-sp-flags-preserve-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100 D28000A0 F100141F D28000E1 8B214FFF 9A9F17E0 D65F03C0

run-addext32-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000020 52802462 0B2203E0 D65F03C0

run-subext32-sp-source-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x1000003E8 12800002 4B22A7E0 D65F03C0

run-addext32-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x100000020 52802462 0B2203FF 910003E0 D65F03C0

run-subext32-sp-dst-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x1000003E8 12800002 4B22A7FF 910003E0 D65F03C0

run-addsext64-uxtw-example: tiny_dbt
	./tiny_dbt D28000A1 D28000E2 AB224C20 D65F03C0

run-subsext64-sxtw-example: tiny_dbt
	./tiny_dbt D2800C81 92800002 EB22C820 D65F03C0

run-addsext32-uxtb-example: tiny_dbt
	./tiny_dbt 52800021 52802462 2B220020 D65F03C0

run-subsext32-sxth-example: tiny_dbt
	./tiny_dbt 52807D01 12800002 6B22A420 D65F03C0

run-addsext64-zr-source-example: tiny_dbt
	./tiny_dbt D28000E2 AB2243E0 D65F03C0

run-subsext64-zr-source-example: tiny_dbt
	./tiny_dbt D28000E2 EB2243E0 9A9F17E0 D65F03C0

run-addsext32-zr-source-example: tiny_dbt
	./tiny_dbt 528000E2 2B2203E0 D65F03C0

run-subsext32-zr-source-example: tiny_dbt
	./tiny_dbt 528000E2 6B2203E0 1A9F17E0 D65F03C0

run-cmnext64-zr-eq-example: tiny_dbt
	./tiny_dbt AB3F43FF 9A9F17E0 D65F03C0

run-cmpext64-zr-eq-example: tiny_dbt
	./tiny_dbt EB3F43FF 9A9F17E0 D65F03C0

run-cmnext32-zr-eq-example: tiny_dbt
	./tiny_dbt 2B3F03FF 1A9F17E0 D65F03C0

run-cmpext32-zr-eq-example: tiny_dbt
	./tiny_dbt 6B3F03FF 1A9F17E0 D65F03C0

run-cmnext64-eq-example: tiny_dbt
	./tiny_dbt 92800001 D2800022 AB22403F 9A9F17E0 D65F03C0

run-cmpext64-eqfalse-example: tiny_dbt
	./tiny_dbt D2800C81 92800002 EB22C83F 9A9F17E0 D65F03C0

run-orrreg32-example: tiny_dbt
	./tiny_dbt 52800500 52800041 2A010000 D65F03C0

run-ornreg32-example: tiny_dbt
	./tiny_dbt 52800500 52800042 2A220000 D65F03C0

run-mvn32-alias-example: tiny_dbt
	./tiny_dbt 52800541 2A2103E0 D65F03C0

run-eorreg32-example: tiny_dbt
	./tiny_dbt 52800500 52800041 4A010000 D65F03C0

run-andsreg32-example: tiny_dbt
	./tiny_dbt 52800540 528005E1 6A010000 D65F03C0

run-bicsreg32-example: tiny_dbt
	./tiny_dbt 528005E0 528000A1 6A210000 D65F03C0

run-cmpreg32-example: tiny_dbt
	./tiny_dbt 528000A0 528000A1 6B01001F 54000040 52800000 D65F03C0

run-ccmpreg64-true-example: tiny_dbt
	./tiny_dbt D28000A1 D28000A2 EB02003F D28000E3 D28000E4 FA440060 54000060 D2800000 D65F03C0 D2800020 D65F03C0

run-ccmpreg64-false-nzcv-example: tiny_dbt
	./tiny_dbt D2800021 D2800042 EB02003F D2800123 D2800104 FA440064 54000060 D2800000 D65F03C0 D2800040 D65F03C0

run-ccmpimm64-true-example: tiny_dbt
	./tiny_dbt D2800141 EB01003F D28000E2 FA470840 54000060 D2800000 D65F03C0 D2800060 D65F03C0

run-ccmpimm32-false-nzcv-example: tiny_dbt
	./tiny_dbt 52800021 52800042 6B02003F 52800123 7A410864 54000060 D2800000 D65F03C0 D2800080 D65F03C0

run-ccmpreg32-true-example: tiny_dbt
	./tiny_dbt 528000A1 528000A2 6B02003F 528000E3 528000E4 7A440060 54000060 D2800000 D65F03C0 D28000A0 D65F03C0

run-ccmnreg64-true-example: tiny_dbt
	./tiny_dbt D28000A1 EB01003F D2800023 D2800024 BA440060 54000061 D2800000 D65F03C0 D2800020 D65F03C0

run-ccmnreg64-false-nzcv-example: tiny_dbt
	./tiny_dbt D2800021 D2800042 EB02003F D2800023 D2800024 BA440064 54000060 D2800000 D65F03C0 D2800040 D65F03C0

run-ccmnimm32-true-example: tiny_dbt
	./tiny_dbt 528000A1 6B01003F 52800023 3A410860 54000061 D2800000 D65F03C0 D2800060 D65F03C0

run-ccmnimm64-false-nzcv-example: tiny_dbt
	./tiny_dbt D2800021 D2800042 EB02003F D2800023 BA410864 54000060 D2800000 D65F03C0 D2800080 D65F03C0

run-fcmpd-lt-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F03F000000000000000000000000000000400000000000000000 D2800001 3DC00021 3DC00422 1E622020 5400006B D2800000 D65F03C0 D2800020 D65F03C0

run-fcmpd-imm0-eq-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:00000000000000800000000000000000 D2800001 3DC00021 1E602028 54000060 D2800000 D65F03C0 D2800040 D65F03C0

run-fcmpe-d-unordered-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F87F0000000000000000 D2800001 3DC00021 1E602038 54000066 D2800000 D65F03C0 D2800060 D65F03C0

run-fadds-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0000A03F0000000000000000000000000000204000000000000000000000000000000000000000000000000000000000 D2800001 3DC00022 3DC00423 1E232840 3D800820 B9402020 D65F03C0

run-faddd-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F83F00000000000000000000000000000240000000000000000000000000000000000000000000000000 D2800001 3DC00022 3DC00423 1E632840 3D800820 F9401020 D65F03C0

run-fsubs-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0000B0400000000000000000000000000000004000000000000000000000000000000000000000000000000000000000 D2800001 3DC00022 3DC00423 1E233840 3D800820 B9402020 D65F03C0

run-fsubd-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000164000000000000000000000000000000040000000000000000000000000000000000000000000000000 D2800001 3DC00022 3DC00423 1E633840 3D800820 F9401020 D65F03C0

run-fmuls-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0000C03F0000000000000000000000000000004000000000000000000000000000000000000000000000000000000000 D2800001 3DC00022 3DC00423 1E230840 3D800820 B9402020 D65F03C0

run-fmuld-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F83F00000000000000000000000000000040000000000000000000000000000000000000000000000000 D2800001 3DC00022 3DC00423 1E630840 3D800820 F9401020 D65F03C0

run-fdivd-example: tiny_dbt
	./tiny_dbt D2E80301 D2E80002 9E670021 9E670042 1E621820 9E660000 D65F03C0

run-fmov-ws-roundtrip-example: tiny_dbt
	./tiny_dbt 5297DDE0 72BBD5A0 1E270001 1E260020 D65F03C0

run-fmov-xd-roundtrip-example: tiny_dbt
	./tiny_dbt D29BDE00 F2B35780 F2CACF00 F2E24680 9E670001 9E660020 D65F03C0

run-scvtf-fcvtzs64-example: tiny_dbt
	./tiny_dbt D2800540 9E620001 9E780020 D65F03C0

run-ucvtf-fcvtzu64-example: tiny_dbt
	./tiny_dbt D2800540 9E630001 9E790020 D65F03C0

run-ucvtf-fcvtzu64-high-example: tiny_dbt
	./tiny_dbt D2F00000 9E630001 9E790020 D65F03C0

run-ucvtf-fcvtzu32-high-example: tiny_dbt
	./tiny_dbt 52B00000 1E230001 1E390020 D65F03C0

run-fccmpd-true-lt-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F03F000000000000000000000000000000400000000000000000 D2800001 EB01003F 3DC00021 3DC00422 1E620424 5400006B D2800000 D65F03C0 D2800020 D65F03C0

run-fccmps-false-nzcv-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0000803F00000000000000000000000000000040000000000000000000000000 D2800001 D2800022 EB02003F 3DC00021 3DC00422 1E220426 54000060 D2800000 D65F03C0 D2800040 D65F03C0

run-fccmpd-unordered-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F87F0000000000000000000000000000F03F0000000000000000 D2800001 EB01003F 3DC00021 3DC00422 1E62E420 54000066 D2800000 D65F03C0 D2800060 D65F03C0

run-fccmped-unordered-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:000000000000F87F0000000000000000000000000000F03F0000000000000000 D2800001 EB01003F 3DC00021 3DC00422 1E62E430 54000066 D2800000 D65F03C0 D2800080 D65F03C0

run-unsupported-log-example: tiny_dbt
	@rm -f /tmp/tiny_dbt_unsupported.log; \
	./tiny_dbt --log-unsupported /tmp/tiny_dbt_unsupported.log FFFFFFFF D65F03C0 || true; \
	cat /tmp/tiny_dbt_unsupported.log

run-unsupported-unreached-example: tiny_dbt
	@rm -f /tmp/tiny_dbt_unsupported.log; \
	./tiny_dbt --log-unsupported /tmp/tiny_dbt_unsupported.log 14000002 FFFFFFFF D2800540 D65F03C0; \
	test ! -f /tmp/tiny_dbt_unsupported.log

run-elf-symbol-example: tiny_dbt
	@lib=/tmp/tiny_dbt_libmain.so; \
	unzip -p /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk lib/arm64-v8a/libmain.so > $$lib; \
	./tiny_dbt --elf-file $$lib --elf-symbol JNI_OnLoad

run-elf-branch-trampoline-example: tiny_dbt
	@lib=/tmp/tiny_dbt_libcrash_trampoline.so; \
	unzip -p /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk lib/arm64-v8a/libcrashlytics-trampoline.so > $$lib; \
	./tiny_dbt --set-reg sp=0x8000 --elf-file $$lib --elf-symbol main

run-elf-import-stub-example: tiny_dbt
	@lib=/tmp/tiny_dbt_libcrash_trampoline.so; \
	unzip -p /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk lib/arm64-v8a/libcrashlytics-trampoline.so > $$lib; \
	./tiny_dbt --set-reg sp=0x8000 --elf-file $$lib --elf-symbol main \
		--elf-import-stub __libc_init=11 --elf-import-stub __cxa_atexit=22 \
		--elf-import-stub dlopen=33 --elf-import-stub dlsym=44 \
		--elf-import-stub dlerror=55 --elf-import-stub __android_log_print=66

run-elf-import-callback-example: tiny_dbt
	@lib=/tmp/tiny_dbt_libcrash_trampoline.so; \
	unzip -p /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk lib/arm64-v8a/libcrashlytics-trampoline.so > $$lib; \
	./tiny_dbt --set-reg sp=0x8000 --set-reg x1=0x1234 --elf-file $$lib --elf-symbol main \
		--elf-import-callback __libc_init=ret_x1 --elf-import-callback __cxa_atexit=add_x0_x1 \
		--elf-import-callback dlopen=nonnull_x0 --elf-import-callback dlsym=ret_sp \
		--elf-import-callback dlerror=sub_x0_x1 --elf-import-callback __android_log_print=ret_x0

run-elf-import-trace-example: tiny_dbt
	@lib=/tmp/tiny_dbt_libcrash_trampoline.so; \
	trace=/tmp/tiny_dbt_import_trace.log; \
	rm -f $$trace; \
	unzip -p /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk lib/arm64-v8a/libcrashlytics-trampoline.so > $$lib; \
	./tiny_dbt --set-reg sp=0x8000 --elf-file $$lib --elf-symbol main \
		--elf-import-stub dlsym=44 --elf-import-callback __android_log_print=ret_x0 \
		--elf-import-trace $$trace; \
	echo "trace file: $$trace"; \
	cat $$trace

run-elf-import-preset-example: tiny_dbt
	@lib=/tmp/tiny_dbt_libcrash_trampoline.so; \
	trace=/tmp/tiny_dbt_import_preset_trace.log; \
	rm -f $$trace; \
	unzip -p /home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk lib/arm64-v8a/libcrashlytics-trampoline.so > $$lib; \
	./tiny_dbt --set-reg sp=0x8000 --elf-file $$lib --elf-symbol main \
		--elf-import-preset android-basic --elf-import-trace $$trace; \
	echo "trace file: $$trace"; \
	cat $$trace

run-import-callback-retx1-example: tiny_dbt
	./tiny_dbt --set-reg x1=0x12345678 D454A220 D65F03C0

run-import-callback-add-example: tiny_dbt
	./tiny_dbt --set-reg x0=2 --set-reg x1=40 D454A400 D65F03C0

run-import-callback-sp-example: tiny_dbt
	./tiny_dbt --set-reg sp=0x8888 D454A600 D65F03C0

run-import-callback-alloc-example: tiny_dbt
	./tiny_dbt --set-reg x0=32 D454AA00 D65F03C0

run-import-callback-free-example: tiny_dbt
	./tiny_dbt --set-reg x0=4096 --set-reg heap_base=4096 --set-reg heap_brk=4112 --set-reg heap_last_ptr=4096 --set-reg heap_last_size=16 D454AA20 D65F03C0

run-import-callback-alloc-free-example: tiny_dbt
	./tiny_dbt --set-reg x0=32 D454AA00 D454AA20 D65F03C0

run-import-callback-calloc-example: tiny_dbt
	./tiny_dbt --set-reg x0=4 --set-reg x1=8 D454AA40 D65F03C0

run-import-callback-calloc-zero-example: tiny_dbt
	./tiny_dbt --set-reg x0=1 --set-reg x1=8 --mem-write 0x1000:FFFFFFFFFFFFFFFF D454AA40 F9400000 D65F03C0

run-import-callback-realloc-example: tiny_dbt
	./tiny_dbt --set-reg x0=4096 --set-reg x1=32 --set-reg heap_base=4096 --set-reg heap_brk=4112 --set-reg heap_last_ptr=4096 --set-reg heap_last_size=16 D454AA60 D454AA20 D65F03C0

run-import-callback-realloc-null-example: tiny_dbt
	./tiny_dbt --set-reg x0=0 --set-reg x1=32 D454AA60 D65F03C0

run-import-callback-memcpy-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=0x20 --set-reg x2=8 --mem-write 0x20:1122334455667788 --mem-read 0x40:8 D454AA80 D65F03C0

run-import-callback-memset-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=0xAB --set-reg x2=8 --mem-read 0x40:8 D454AAA0 D65F03C0

run-import-callback-memcmp-eq-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x30 --set-reg x2=8 --mem-write 0x20:1122334455667788 --mem-write 0x30:1122334455667788 D454AAC0 D65F03C0

run-import-callback-memcmp-ne-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x30 --set-reg x2=8 --mem-write 0x20:1122334455667788 --mem-write 0x30:1022334455667788 D454AAC0 D65F03C0

run-import-callback-memmove-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x24 --set-reg x1=0x20 --set-reg x2=8 --mem-write 0x20:1122334455667788 --mem-read 0x24:8 D454AAE0 D65F03C0

run-import-callback-strnlen-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=16 --mem-write 0x40:48656C6C6F00 D454AB00 D65F03C0

run-import-callback-strnlen-max-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=4 --mem-write 0x40:41424344 D454AB00 D65F03C0

run-import-callback-strlen-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --mem-write 0x40:48656C6C6F00 D454AB20 D65F03C0

run-import-callback-strcmp-eq-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x30 --mem-write 0x20:68656C6C6F00 --mem-write 0x30:68656C6C6F00 D454AB40 D65F03C0

run-import-callback-strcmp-ne-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x30 --mem-write 0x20:626F7800 --mem-write 0x30:616F7800 D454AB40 D65F03C0

run-import-callback-strncmp-eq-prefix-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x30 --set-reg x2=5 --mem-write 0x20:68656C6C6F3100 --mem-write 0x30:68656C6C6F3200 D454AB60 D65F03C0

run-import-callback-strncmp-ne-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x30 --set-reg x2=6 --mem-write 0x20:68656C6C6F3200 --mem-write 0x30:68656C6C6F3100 D454AB60 D65F03C0

run-import-callback-strcpy-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x50 --set-reg x1=0x20 --mem-write 0x20:48656C6C6F00 --mem-read 0x50:6 D454AB80 D65F03C0

run-import-callback-strncpy-pad-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x50 --set-reg x1=0x20 --set-reg x2=8 --mem-write 0x20:486900 --mem-read 0x50:8 D454ABA0 D65F03C0

run-import-callback-strchr-hit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x6C --mem-write 0x20:68656C6C6F00 D454ABC0 D65F03C0

run-import-callback-strchr-miss-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x7A --mem-write 0x20:68656C6C6F00 D454ABC0 D65F03C0

run-import-callback-strchr-nul-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x00 --mem-write 0x20:68656C6C6F00 D454ABC0 D65F03C0

run-import-callback-strrchr-hit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x61 --mem-write 0x20:62616E616E617300 D454ABE0 D65F03C0

run-import-callback-strrchr-miss-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x7A --mem-write 0x20:62616E616E617300 D454ABE0 D65F03C0

run-import-callback-strstr-hit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x40 --mem-write 0x20:62616E616E6100 --mem-write 0x40:6E616E00 D454AC00 D65F03C0

run-import-callback-strstr-miss-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x40 --mem-write 0x20:62616E616E6100 --mem-write 0x40:78797A00 D454AC00 D65F03C0

run-import-callback-strstr-empty-needle-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x40 --mem-write 0x20:62616E616E6100 --mem-write 0x40:00 D454AC00 D65F03C0

run-import-callback-memchr-hit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x44 --set-reg x2=6 --mem-write 0x20:112233445566 D454AC20 D65F03C0

run-import-callback-memchr-miss-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x99 --set-reg x2=6 --mem-write 0x20:112233445566 D454AC20 D65F03C0

run-import-callback-memchr-limit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x55 --set-reg x2=4 --mem-write 0x20:112233445566 D454AC20 D65F03C0

run-import-callback-memrchr-hit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x61 --set-reg x2=7 --mem-write 0x20:62616E616E6173 D454AC40 D65F03C0

run-import-callback-memrchr-miss-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x7A --set-reg x2=7 --mem-write 0x20:62616E616E6173 D454AC40 D65F03C0

run-import-callback-atoi-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --mem-write 0x20:202B343200 D454AC60 D65F03C0

run-import-callback-atoi-neg-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --mem-write 0x20:2D313700 D454AC60 D65F03C0

run-import-callback-strtol-base0-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=0 --mem-write 0x20:307832417A00 --mem-read 0x80:8 D454AC80 D65F03C0

run-import-callback-strtol-base16-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=16 --mem-write 0x20:324100 --mem-read 0x80:8 D454AC80 D65F03C0

run-import-callback-strtol-invalid-base-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=1 --mem-write 0x20:31323300 --mem-read 0x80:8 D454AC80 D65F03C0

run-import-callback-retneg1-example: tiny_dbt
	./tiny_dbt D454A060 D65F03C0

run-import-callback-retneg1-enosys-example: tiny_dbt
	./tiny_dbt D454AF80 D65F03C0

run-import-callback-retneg1-eagain-example: tiny_dbt
	./tiny_dbt D454AFA0 D65F03C0

run-import-callback-retneg1-eintr-example: tiny_dbt
	./tiny_dbt D454AFC0 D65F03C0

run-import-callback-retneg1-eacces-example: tiny_dbt
	./tiny_dbt D454B180 D65F03C0

run-import-callback-retneg1-enoent-example: tiny_dbt
	./tiny_dbt D454B1A0 D65F03C0

run-import-callback-retneg1-eperm-example: tiny_dbt
	./tiny_dbt D454B1C0 D65F03C0

run-import-callback-retneg1-etimedout-example: tiny_dbt
	./tiny_dbt D454B1E0 D65F03C0

run-import-callback-errno-slot-example: tiny_dbt
	./tiny_dbt D454AFE0 AA0003E1 D454AF80 F9400020 D65F03C0

run-import-callback-handle-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x1234 D454B000 D65F03C0

run-import-callback-gmtime-example: tiny_dbt
	./tiny_dbt --set-reg x0=0 D454B0E0 D65F03C0

run-import-callback-ctime-example: tiny_dbt
	./tiny_dbt --set-reg x0=0 D454B100 D65F03C0

run-import-callback-daylight-example: tiny_dbt
	./tiny_dbt D454B140 D65F03C0

run-import-callback-timezone-example: tiny_dbt
	./tiny_dbt D454B160 D65F03C0

run-import-callback-strtoul-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x100 --set-reg x2=10 --mem-write 0x20:3432393439363732393561626300 --mem-read 0x100:8 D454ADA0 D65F03C0

run-import-callback-posix-memalign-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x180 --set-reg x1=0x40 --set-reg x2=0x30 --mem-read 0x180:8 D454ADC0 D65F03C0

run-import-callback-posix-memalign-einval-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x180 --set-reg x1=24 --set-reg x2=0x30 D454ADC0 D65F03C0

run-import-callback-basename-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --mem-write 0x20:2F666F6F2F62617200 D454ADE0 D65F03C0

run-import-callback-strdup-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --mem-write 0x20:68656C6C6F00 --mem-read 0x1000:8 D454AE00 D65F03C0

run-import-callback-strtof-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x90 --mem-write 0x20:332E3578797A00 --mem-read 0x90:8 D454AE20 D65F03C0

run-import-callback-pow-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x4000000000000000 --set-reg x1=0x4000000000000000 D454AE40 D65F03C0

run-import-callback-sqrt-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x4022000000000000 D454AE60 D65F03C0

run-import-callback-cos-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x0 D454AE80 D65F03C0

run-import-callback-tan-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x0 D454AEA0 D65F03C0

run-import-callback-exp-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x0 D454B200 D65F03C0

run-import-callback-log-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x3FF0000000000000 D454B220 D65F03C0

run-import-callback-log10-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x4024000000000000 D454B240 D65F03C0

run-import-callback-floor-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x400E000000000000 D454B260 D65F03C0

run-import-callback-ceil-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x400A000000000000 D454B280 D65F03C0

run-import-callback-trunc-example: tiny_dbt
	./tiny_dbt --set-reg x0=0xC00E000000000000 D454B2A0 D65F03C0

run-import-callback-fmod-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x4016000000000000 --set-reg x1=0x4000000000000000 D454B2C0 D65F03C0

run-import-callback-sin-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x0 D454B2E0 D65F03C0

run-import-callback-sinh-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x0 D454B300 D65F03C0

run-import-callback-tanh-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x0 D454B320 D65F03C0

run-import-callback-sinf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x3FC90FDB D454B340 D65F03C0

run-import-callback-sincosf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x3FC90FDB --set-reg x1=0x120 --set-reg x2=0x124 --mem-read 0x120:8 D454B360 D65F03C0

run-import-callback-exp2f-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40000000 D454B380 D65F03C0

run-import-callback-log2f-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40800000 D454B3A0 D65F03C0

run-import-callback-log10f-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x41200000 D454B3C0 D65F03C0

run-import-callback-lround-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x400B333333333333 D454B3E0 D65F03C0

run-import-callback-islower-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x61 D454AEC0 D65F03C0

run-import-callback-isspace-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 D454AEE0 D65F03C0

run-import-callback-isxdigit-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x66 D454AF00 D65F03C0

run-import-callback-isupper-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x41 D454AF20 D65F03C0

run-import-callback-toupper-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x61 D454AF40 D65F03C0

run-import-callback-tolower-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x41 D454AF60 D65F03C0

run-import-callback-snprintf-mixed-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=32 --set-reg x2=0x20 --set-reg x3=0x30 --set-reg x4=1337 --mem-write 0x20:25732D257500 --mem-write 0x30:666F6F00 --mem-read 0x40:16 D454ACA0 D65F03C0

run-import-callback-snprintf-trunc-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x50 --set-reg x1=8 --set-reg x2=0x20 --set-reg x3=123456 --mem-write 0x20:76616C75653D257500 --mem-read 0x50:8 D454ACA0 D65F03C0

run-import-callback-snprintf-widthprec-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0x20 --set-reg x3=0x7B --set-reg x4=0x30 --set-reg x5=0xFFFFFFFFFFFFFFD6 --mem-write 0x20:5B253038787C252E33737C256C6C645D00 --mem-write 0x30:62616E616E6100 --mem-read 0x40:24 D454ACA0 D65F03C0

run-import-callback-snprintf-starwidth-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0x20 --set-reg x3=6 --set-reg x4=4 --set-reg x5=42 --mem-write 0x20:5B252A2E2A755D00 --mem-read 0x40:16 D454ACA0 D65F03C0

run-import-callback-snprintf-float-n-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0x20 --set-reg x3=0x400C000000000000 --set-reg x4=0x180 --set-reg x5=0x4008000000000000 --mem-write 0x20:663D25362E32667C6E3D256E7C673D256700 --mem-read 0x40:24 --mem-read 0x180:4 D454ACA0 D65F03C0

run-import-callback-snprintf-stack-varargs-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0x20 --set-reg x3=1 --set-reg x4=2 --set-reg x5=3 --set-reg x6=4 --set-reg x7=5 --set-reg sp=0x300 --mem-write 0x300:0600000000000000 --mem-write 0x20:256420256420256420256420256420256400 --mem-read 0x40:24 D454ACA0 D65F03C0

run-import-callback-vsnprintf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0x20 --set-reg x3=0x300 --mem-write 0x300:2A000000000000000300000000000000 --mem-write 0x20:25752D257500 --mem-read 0x40:16 D454AD00 D65F03C0

run-import-callback-vsnprintf-chk-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0 --set-reg x3=64 --set-reg x4=0x20 --set-reg x5=0x300 --mem-write 0x300:2A000000000000000300000000000000 --mem-write 0x20:25752D257500 --mem-read 0x40:16 D454AD40 D65F03C0

run-import-callback-vfprintf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x1234 --set-reg x1=0x20 --set-reg x2=0x300 --mem-write 0x300:2A000000000000000300000000000000 --mem-write 0x20:25752D257500 D454AD60 D65F03C0

run-import-callback-vasprintf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x180 --set-reg x1=0x20 --set-reg x2=0x300 --mem-write 0x300:2A000000000000000300000000000000 --mem-write 0x20:25752D257500 --mem-read 0x180:8 --mem-read 0x1000:16 D454AD80 D65F03C0

run-import-callback-snprintf-inf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x40 --set-reg x1=64 --set-reg x2=0x20 --set-reg x3=0x7FF0000000000000 --set-reg x4=0xFFF0000000000000 --set-reg x5=0x7FF8000000000000 --mem-write 0x20:256620257C25667C256700 --mem-read 0x40:24 D454ACA0 D65F03C0

run-import-callback-snprintf-trunc-edge-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x60 --set-reg x1=1 --set-reg x2=0x20 --set-reg x3=12345 --mem-write 0x20:256400 --mem-read 0x60:1 D454ACA0 D65F03C0

run-import-callback-strtod-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x90 --mem-write 0x20:202D31322E3561626300 --mem-read 0x90:8 D454ACC0 D65F03C0

run-import-callback-strtod-nan-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x90 --mem-write 0x20:6E616E283132332900 --mem-read 0x90:8 D454ACC0 D65F03C0

run-import-callback-sscanf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=0x200 --set-reg x3=0x208 --set-reg x4=0x220 --mem-write 0x20:3132332037622068656C6C6F00 --mem-write 0x80:256420257820257300 --mem-read 0x200:4 --mem-read 0x208:4 --mem-read 0x220:6 D454ACE0 D65F03C0

run-import-callback-sscanf-float-n-scanset-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=0x240 --set-reg x3=0x250 --set-reg x4=0x280 --set-reg x5=0x288 --mem-write 0x20:31322E3735206170706C65732D34322100 --mem-write 0x80:256620255B5E2D5D2D2564256E00 --mem-read 0x240:4 --mem-read 0x250:8 --mem-read 0x280:4 --mem-read 0x288:4 D454ACE0 D65F03C0

run-import-callback-sscanf-stack-varargs-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=0x200 --set-reg x3=0x208 --set-reg x4=0x210 --set-reg x5=0x218 --set-reg x6=0x220 --set-reg x7=0x228 --set-reg sp=0x300 --mem-write 0x300:3002000000000000 --mem-write 0x20:3120322033203420352036203700 --mem-write 0x80:256420256420256420256420256420256420256400 --mem-read 0x200:4 --mem-read 0x208:4 --mem-read 0x210:4 --mem-read 0x218:4 --mem-read 0x220:4 --mem-read 0x228:4 --mem-read 0x230:4 D454ACE0 D65F03C0

run-import-callback-vsscanf-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=0x300 --mem-write 0x20:343220666600 --mem-write 0x80:256420257800 --mem-write 0x300:00020000000000000802000000000000 --mem-read 0x200:4 --mem-read 0x208:4 D454AD20 D65F03C0

run-import-callback-sscanf-scanset-invert-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x20 --set-reg x1=0x80 --set-reg x2=0x240 --set-reg x3=0x260 --mem-write 0x20:414243313233212A00 --mem-write 0x80:255B5E302D395D256E00 --mem-read 0x240:10 --mem-read 0x260:4 D454ACE0 D65F03C0

run-kingshot-import-profile:
	./scripts/generate_kingshot_import_profile.sh $(KSHOT_APK_PATH) lib/arm64-v8a/libmain.so $(KSHOT_PROFILE_MODE)

run-kingshot-import-profile-strict:
	./scripts/generate_kingshot_import_profile.sh $(KSHOT_APK_PATH) lib/arm64-v8a/libmain.so strict

run-kingshot-import-profile-compat:
	./scripts/generate_kingshot_import_profile.sh $(KSHOT_APK_PATH) lib/arm64-v8a/libmain.so compat

run-kingshot-import-profile-all:
	./scripts/generate_kingshot_all_import_profiles.sh $(KSHOT_APK_PATH) $(KSHOT_PROFILE_MODE)

run-kingshot-import-profile-all-strict:
	./scripts/generate_kingshot_all_import_profiles.sh $(KSHOT_APK_PATH) strict

run-kingshot-import-profile-all-compat:
	./scripts/generate_kingshot_all_import_profiles.sh $(KSHOT_APK_PATH) compat

run-kingshot-coverage-gate:
	./scripts/check_kingshot_coverage.sh

run-kingshot-smoke: tiny_dbt
	KSHOT_PROFILE_MODE=$(KSHOT_PROFILE_MODE) ./scripts/run_kingshot_smoke.sh $(KSHOT_APK_PATH)

run-kingshot-smoke-matrix: tiny_dbt
	KSHOT_PROFILE_MODE=$(KSHOT_PROFILE_MODE) ./scripts/run_kingshot_smoke_matrix.sh $(KSHOT_APK_PATH)

run-kingshot-smoke-matrix-ci: tiny_dbt
	KSHOT_PROFILE_MODE=$(KSHOT_PROFILE_MODE) SMOKE_FAIL_ON_ERROR=1 ./scripts/run_kingshot_smoke_matrix.sh $(KSHOT_APK_PATH) 5 1 1

run-nativebridge-skeleton-build:
	$(MAKE) -C nativebridge_skeleton

run-nativebridge-skeleton-demo:
	$(MAKE) run-kingshot-import-profile
	TINY_NB_PROFILE_CALLBACKS=$(CURDIR)/profiles/kingshot_libmain_import_callbacks.txt \
	TINY_NB_PROFILE_STUBS=$(CURDIR)/profiles/kingshot_libmain_import_stubs.txt \
	$(MAKE) -C nativebridge_skeleton run-demo

run-nativebridge-skeleton-jni-probe:
	$(MAKE) -C nativebridge_skeleton run-jni-probe

verify-kingshot: tiny_dbt
	$(MAKE) run-import-callback-vsnprintf-chk-example
	$(MAKE) run-import-callback-vfprintf-example
	$(MAKE) run-import-callback-vasprintf-example
	$(MAKE) run-import-callback-retneg1-example
	$(MAKE) run-import-callback-retneg1-enosys-example
	$(MAKE) run-import-callback-retneg1-eagain-example
	$(MAKE) run-import-callback-retneg1-eintr-example
	$(MAKE) run-import-callback-retneg1-eacces-example
	$(MAKE) run-import-callback-retneg1-enoent-example
	$(MAKE) run-import-callback-retneg1-eperm-example
	$(MAKE) run-import-callback-retneg1-etimedout-example
	$(MAKE) run-import-callback-errno-slot-example
	$(MAKE) run-import-callback-handle-example
	$(MAKE) run-import-callback-gmtime-example
	$(MAKE) run-import-callback-ctime-example
	$(MAKE) run-import-callback-daylight-example
	$(MAKE) run-import-callback-timezone-example
	$(MAKE) run-import-callback-basename-example
	$(MAKE) run-import-callback-strdup-example
	$(MAKE) run-import-callback-strtof-example
	$(MAKE) run-import-callback-pow-example
	$(MAKE) run-import-callback-sqrt-example
	$(MAKE) run-import-callback-cos-example
	$(MAKE) run-import-callback-tan-example
	$(MAKE) run-import-callback-exp-example
	$(MAKE) run-import-callback-log-example
	$(MAKE) run-import-callback-log10-example
	$(MAKE) run-import-callback-floor-example
	$(MAKE) run-import-callback-ceil-example
	$(MAKE) run-import-callback-trunc-example
	$(MAKE) run-import-callback-fmod-example
	$(MAKE) run-import-callback-sin-example
	$(MAKE) run-import-callback-sinh-example
	$(MAKE) run-import-callback-tanh-example
	$(MAKE) run-import-callback-sinf-example
	$(MAKE) run-import-callback-sincosf-example
	$(MAKE) run-import-callback-exp2f-example
	$(MAKE) run-import-callback-log2f-example
	$(MAKE) run-import-callback-log10f-example
	$(MAKE) run-import-callback-lround-example
	$(MAKE) run-import-callback-islower-example
	$(MAKE) run-import-callback-isspace-example
	$(MAKE) run-import-callback-isxdigit-example
	$(MAKE) run-import-callback-isupper-example
	$(MAKE) run-import-callback-toupper-example
	$(MAKE) run-import-callback-tolower-example
	$(MAKE) run-import-callback-strtoul-example
	$(MAKE) run-import-callback-posix-memalign-example
	$(MAKE) run-kingshot-import-profile-all
	./scripts/check_kingshot_coverage.sh
	KSHOT_PROFILE_MODE=$(KSHOT_PROFILE_MODE) ./scripts/run_kingshot_smoke_matrix.sh $(KSHOT_APK_PATH) 10 2 2

verify-kingshot-ci: tiny_dbt
	$(MAKE) verify-kingshot
	$(MAKE) run-kingshot-smoke-matrix-ci

run-orrreg64-zr-alias-example: tiny_dbt
	./tiny_dbt D2800541 AA0103E0 D65F03C0

run-ornreg64-example: tiny_dbt
	./tiny_dbt D28000A0 D2800042 AA220000 D65F03C0

run-mvn64-alias-example: tiny_dbt
	./tiny_dbt D2800541 AA2103E0 D65F03C0

run-orrreg32-zr-alias-example: tiny_dbt
	./tiny_dbt 52800541 2A0103E0 D65F03C0

run-eorreg64-zr-source-example: tiny_dbt
	./tiny_dbt D2800541 CA1F0020 D65F03C0

run-andsreg64-zr-source-example: tiny_dbt
	./tiny_dbt D28000A1 EA1F0020 9A9F17E0 D65F03C0

run-bicsreg64-zr-source-example: tiny_dbt
	./tiny_dbt D28000A1 EA3F0020 9A9F17E0 D65F03C0

run-cmpreg64-zr-source-example: tiny_dbt
	./tiny_dbt D2800001 EB1F003F 9A9F17E0 D65F03C0

run-orrreg64-zr-discard-flags-example: tiny_dbt
	./tiny_dbt D28000A0 F100141F D2800541 AA0103FF 9A9F17E0 D65F03C0

run-shift32-lsr-example: tiny_dbt
	./tiny_dbt 52800500 52800101 0B410800 D65F03C0

run-reg8-addimm-example: tiny_dbt
	./tiny_dbt D2800508 91000900 D65F03C0

run-reg9-memory-example: tiny_dbt
	./tiny_dbt D2800009 D280054A F900012A D2800000 F9400120 D65F03C0

run-reg10-addreg-example: tiny_dbt
	./tiny_dbt D280046A D28000E8 8B08014A 91000140 D65F03C0

run-spill-addimm-example: tiny_dbt
	./tiny_dbt D280050B 91000960 D65F03C0

run-spill-movk-example: tiny_dbt
	./tiny_dbt D28ACF0C F2A2468C 91000180 D65F03C0

run-spill-addreg-example: tiny_dbt
	./tiny_dbt D280050B D280004C 8B0C0160 D65F03C0

run-spill-csel-eq-example: tiny_dbt
	./tiny_dbt D280054B D28000EC F100A97F 9A8C0160 D65F03C0

run-spill-csel-ne-example: tiny_dbt
	./tiny_dbt D280054B D28000EC F100A97F 9A8C1160 D65F03C0

run-spill-cbz-example: tiny_dbt
	./tiny_dbt D2800020 D280002B B400004B 9100A400 D65F03C0

run-spill-tbz-example: tiny_dbt
	./tiny_dbt D280000B 3600004B D28000E0 D2800540 D65F03C0

run-spill-memory64-example: tiny_dbt
	./tiny_dbt D280002B D280054C F900016C D2800000 F9400160 D65F03C0

run-spill-memory32-example: tiny_dbt
	./tiny_dbt D280002B D297DDEC B900056C D2800000 B9400560 D65F03C0

run-spill-ldur64-example: tiny_dbt
	./tiny_dbt D280000B D280054C F800816C D2800000 F8408160 D65F03C0

run-spill-byte-example: tiny_dbt
	./tiny_dbt D280002B D280156C 39000D6C D2800000 39400D60 D65F03C0

run-spill-ldrsb-example: tiny_dbt
	./tiny_dbt D280004B D2801FEC 3900016C D2800000 39C00160 D65F03C0

run-spill-memory-oob-example: tiny_dbt
	./tiny_dbt D29FFFEB F9400160 D65F03C0

run-spill-postpre64-example: tiny_dbt
	./tiny_dbt D280002B D280054C F800856C D280000C F85F8D6C 91000180 D65F03C0

run-spill-postpre32-example: tiny_dbt
	./tiny_dbt D280010B D297DDEC B81FCD6C D280000C B840456C 91000180 D65F03C0

run-spill-postpre-ldrsb-example: tiny_dbt
	./tiny_dbt D280002B D2801FEC 3800156C D280000C 38DFFD6C 91000180 D65F03C0

run-spill-pair-postpre64-example: tiny_dbt
	./tiny_dbt D280002B D280014C D280040D A881356C D280000C D280000D A9FF356C 8B0D0180 D65F03C0

run-spill-pair-offset64-example: tiny_dbt
	./tiny_dbt D280000B D28000EC D280046D A900356C D280000C D280000D A940356C 8B0D0180 D65F03C0

run-spill-ldxr-stxr64-example: tiny_dbt
	./tiny_dbt D280002B D280054C C85F7D6D C80E7D6C C85F7D60 D65F03C0

run-spill-stxr64-fail-example: tiny_dbt
	./tiny_dbt D280002B D280054C C80D7D6C 910001A0 D65F03C0

run-spill-ldxr-stxr64-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D280054C C85F7FED C80E7FEC C85F7FE0 D65F03C0

run-spill-stxr64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D280054C C80D7FEC 910001A0 D65F03C0

run-spill-ldaxr-stlxr64-example: tiny_dbt
	./tiny_dbt D280002B D280054C C85FFD6D C80EFD6C C85FFD60 D65F03C0

run-spill-stlxr64-fail-example: tiny_dbt
	./tiny_dbt D280002B D280054C C80DFD6C 910001A0 D65F03C0

run-spill-ldaxr-stlxr64-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D280054C C85FFFED C80EFFEC C85FFFE0 D65F03C0

run-spill-stlxr64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D280054C C80DFFEC 910001A0 D65F03C0

run-spill-ldar-stlr64-example: tiny_dbt
	./tiny_dbt D280002B D280054C C89FFD6C D280000C C8DFFD6C 91000180 D65F03C0

run-spill-ldar-stlr32-example: tiny_dbt
	./tiny_dbt D280002B D297DDEC 889FFD6C D280000C 88DFFD6C 91000180 D65F03C0

run-spill-ldar-stlr64-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D280054C C89FFFEC D280000C C8DFFFEC 91000180 D65F03C0

run-spill-ldar-stlr32-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D297DDEC 889FFFEC D280000C 88DFFFEC 91000180 D65F03C0

run-spill-swp64-example: tiny_dbt
	./tiny_dbt D280002B D28000EC F900016C D280054D F82D816C 9100A980 D65F03C0

run-spill-swp64-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC F90003EC D280054D F82D83EC 9100A980 D65F03C0

run-spill-ldadd64-example: tiny_dbt
	./tiny_dbt D280002B D28000EC F900016C D28000AD F82D016C F940016E 8B0E0180 D65F03C0

run-spill-ldadd64-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC F90003EC D28000AD F82D03EC F94003EE 8B0E0180 D65F03C0

run-spill-cas64-success-example: tiny_dbt
	./tiny_dbt D280002B D28000EC F900016C D2800D2D C8AC7D6D F9400160 D65F03C0

run-spill-cas64-success-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC F90003EC D2800D2D C8AC7FED F94003E0 D65F03C0

run-spill-cas64-fail-example: tiny_dbt
	./tiny_dbt D280002B D28000EC D280012D D280054E F900016E C8AC7D6D 91000580 D65F03C0

run-spill-cas64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC D280012D D280054E F90003EE C8AC7FED 91000580 D65F03C0

run-spill-casp64-success-example: tiny_dbt
	./tiny_dbt D280002B D28000EC D280012D F900016C F900056D D2800C8E D2800CAF 482C7D6E F9400160 F9400561 8B010000 D65F03C0

run-spill-casp64-success-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC D280012D F90003EC F90007ED D2800C8E D2800CAF 482C7FEE F94003E0 F94007E1 8B010000 D65F03C0

run-spill-casp64-fail-example: tiny_dbt
	./tiny_dbt D280002B D280010C D280014D D28000EE D280012F F900016E F900056F D2800C8E D2800CAF 482C7D6E 8B0D0180 D65F03C0

run-spill-casp64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D280010C D280014D D28000EE D280012F F90003EE F90007EF D2800C8E D2800CAF 482C7FEE 8B0D0180 D65F03C0

run-spill-casa64-success-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC F90003EC D2800D2D C8EC7FED F94003E0 D65F03C0

run-spill-casl64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D28000EC D280012D D280054E F90003EE C8ACFFED 91000580 D65F03C0

run-spill-casal32-rtx0-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D297DDEC B90003EC D2824680 88ECFFE0 B94003E0 D65F03C0

run-spill-casb-success-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D2800FEC 390003EC D280084D 08AC7FED 394003E0 D65F03C0

run-spill-caslb-fail-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D2800FEC D2800AAE 390003EE D280084D 08ACFFED 91000180 D65F03C0

run-spill-casah-success-sp-base-example: tiny_dbt
	./tiny_dbt D280002B 9100017F D297DDEC 790003EC D282468D 48EC7FED 794003E0 D65F03C0

stress-spill-atomics: tiny_dbt
	./scripts/stress_spill_atomics.sh $${N:-100}

run-memory-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F9000020 D2800000 F9400020 D65F03C0

run-memory32-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B9000420 D2800000 B9400420 D65F03C0

run-strxzr-imm-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F900003F F9400020 D65F03C0

run-strwzr-imm-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B900043F D2800000 B9400420 D65F03C0

run-ldrxzr-imm-discard-example: tiny_dbt
	./tiny_dbt D2800001 D2800542 F9000022 D28000E0 F940003F D65F03C0

run-ldrwzr-imm-discard-example: tiny_dbt
	./tiny_dbt D2800001 D2800542 B9000022 D28000E0 B940003F D65F03C0

run-oob-example: tiny_dbt
	./tiny_dbt D29FFFE1 F9400020 D65F03C0

run-cond-eq-example: tiny_dbt
	./tiny_dbt D28000A0 F100141F 54000040 D2800000 D65F03C0

run-cond-lt-example: tiny_dbt
	./tiny_dbt D2800060 D28000E1 EB01001F 5400004B D2800000 D65F03C0

run-csel-true-example: tiny_dbt
	./tiny_dbt D28000A0 D2800161 D28002C2 F100141F 9A820020 D65F03C0

run-csel-false-example: tiny_dbt
	./tiny_dbt D28000A0 D2800161 D28002C2 F1001C1F 9A820020 D65F03C0

run-csel32-true-example: tiny_dbt
	./tiny_dbt 528000A0 52800161 528002C2 7100141F 1A820020 D65F03C0

run-csel32-false-example: tiny_dbt
	./tiny_dbt 528000A0 52800161 528002C2 71001C1F 1A820020 D65F03C0

run-csel64-rn-zr-true-example: tiny_dbt
	./tiny_dbt D28000A0 D2800541 F100141F 9A8103E0 D65F03C0

run-csel64-rm-zr-false-example: tiny_dbt
	./tiny_dbt D28000A0 D2800541 F100181F 9A9F0020 D65F03C0

run-csel64-rd-zr-discard-example: tiny_dbt
	./tiny_dbt D28000A0 D2800161 D28002C2 F100141F 9A82003F 9A9F17E0 D65F03C0

run-csel32-rn-zr-true-example: tiny_dbt
	./tiny_dbt 528000A0 52800541 7100141F 1A8103E0 D65F03C0

run-csel32-rm-zr-false-example: tiny_dbt
	./tiny_dbt 528000A0 52800541 7100181F 1A9F0020 D65F03C0

run-csel32-rd-zr-discard-example: tiny_dbt
	./tiny_dbt 528000A0 52800161 528002C2 7100141F 1A82003F 1A9F17E0 D65F03C0

run-csinc32-false-example: tiny_dbt
	./tiny_dbt 52800140 52800281 7100001F 1A810400 D65F03C0

run-csinv64-false-example: tiny_dbt
	./tiny_dbt D2800140 D2801E01 F100001F DA810000 D65F03C0

run-csneg64-false-example: tiny_dbt
	./tiny_dbt D2800140 D28000A1 F100001F DA810400 D65F03C0

run-cset32-eq-example: tiny_dbt
	./tiny_dbt 528000E0 71001C1F 1A9F17E0 D65F03C0

run-cset64-eq-example: tiny_dbt
	./tiny_dbt D28000E0 F1001C1F 9A9F17E0 D65F03C0

run-csetm32-eq-example: tiny_dbt
	./tiny_dbt 528000E0 71001C1F 5A9F13E0 D65F03C0

run-csetm64-eq-example: tiny_dbt
	./tiny_dbt D28000E0 F1001C1F DA9F13E0 D65F03C0

run-ands-example: tiny_dbt
	./tiny_dbt D2801E01 D28001E2 EA020020 54000040 D2800020 D65F03C0

run-tst-example: tiny_dbt
	./tiny_dbt D2800120 D2800061 D2800022 EA02003F 54000040 D28000E0 D65F03C0

run-shift-add-lsl-example: tiny_dbt
	./tiny_dbt D28000A0 D2800061 8B010800 D65F03C0

run-shift-sub-lsr-example: tiny_dbt
	./tiny_dbt D2800280 D2800101 CB410400 D65F03C0

run-shift-cmp-asr-example: tiny_dbt
	./tiny_dbt D2800080 D2800101 EB81041F 54000040 D2800000 D65F03C0

run-orr-shift-example: tiny_dbt
	./tiny_dbt D28001E1 D2800062 AA021020 D65F03C0

run-eor-shift-example: tiny_dbt
	./tiny_dbt D2801FE1 D28001E2 CA021020 D65F03C0

run-bics-example: tiny_dbt
	./tiny_dbt D2801E01 D28001E2 EA220020 54000040 D65F03C0 D2800000 D65F03C0

run-bcond-crossblock-example: tiny_dbt
	./tiny_dbt D28000A0 F100141F 14000002 D503201F 54000040 D2800000 D65F03C0

run-flags-preserve-add-example: tiny_dbt
	./tiny_dbt D28000A0 F100141F 91000421 54000040 D2800000 D65F03C0

run-tbz-example: tiny_dbt
	./tiny_dbt D2800000 36000040 D28000E0 D2800540 D65F03C0

run-tbnz-example: tiny_dbt
	./tiny_dbt D2800020 37000040 D28000E0 D2800540 D65F03C0

run-tbz32-wzr-example: tiny_dbt
	./tiny_dbt D28000E0 3600007F D2800000 D65F03C0 D2800540 D65F03C0

run-tbnz32-wzr-example: tiny_dbt
	./tiny_dbt D28000E0 3700007F D65F03C0 D2800540 D65F03C0

run-tbz64-bit32-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x100000000 B6000060 D28000E0 D65F03C0 D2800540 D65F03C0

run-tbnz64-bit32-example: tiny_dbt
	./tiny_dbt --set-reg x0=0x100000000 B7000060 D28000E0 D65F03C0 D2800540 D65F03C0

run-cbz32-example: tiny_dbt
	./tiny_dbt 52800000 34000060 D28000E0 D65F03C0 D2800540 D65F03C0

run-cbnz32-example: tiny_dbt
	./tiny_dbt 52800020 35000060 D28000E0 D65F03C0 D2800540 D65F03C0

run-cbz32-wzr-example: tiny_dbt
	./tiny_dbt D28000E0 3400007F D2800000 D65F03C0 D2800540 D65F03C0

run-cbnz32-wzr-example: tiny_dbt
	./tiny_dbt D28000E0 3500005F D65F03C0 D2800540 D65F03C0

run-bl-ret-example: tiny_dbt
	./tiny_dbt D2800020 94000002 D65F03C0 9100A400 D65F03C0

run-ret-x1-example: tiny_dbt
	./tiny_dbt D2800540 D2800181 D65F0020

run-ret-midblock-example: tiny_dbt
	./tiny_dbt D2800181 D65F0020 D2800000 D2800540 D65F03C0

run-ret-xzr-example: tiny_dbt
	./tiny_dbt --pc-bytes 4 --set-reg x0=7 14000003 D65F03E0 D503201F

run-br-example: tiny_dbt
	./tiny_dbt D2800201 D61F0020 D2800020 14000001 D2800540 D65F03C0

run-br-midblock-example: tiny_dbt
	./tiny_dbt D2800181 D61F0020 D2800000 D2800540 91000400 D65F03C0

run-br-xzr-example: tiny_dbt
	./tiny_dbt --pc-bytes 4 --set-reg x0=7 --set-reg x30=8 D65F03C0 D61F03E0

run-blr-ret-example: tiny_dbt
	./tiny_dbt D2800201 D63F0020 D65F03C0 14000001 D2800540 D65F03C0

run-blr-xzr-example: tiny_dbt
	./tiny_dbt --pc-bytes 4 --set-reg x0=7 D65F03C0 D63F03E0

run-bl-ret-nested-example: tiny_dbt
	./tiny_dbt 94000003 D65F03C0 D503201F 94000003 91000400 D65F03C0 D2800520 D65F03C0

run-lr-overflow-example: tiny_dbt
	@args=""; i=0; while [ $$i -lt 65 ]; do args="$$args 94000002 D65F03C0"; i=$$((i+1)); done; ./tiny_dbt $$args D2800540 D65F03C0

run-dispatch-version-miss-example: tiny_dbt
	TINY_DBT_INVALIDATE_BEFORE_RUN=1 ./tiny_dbt D2800540 D65F03C0

run-dispatch-version-miss-midblock-example: tiny_dbt
	TINY_DBT_INVALIDATE_BEFORE_RUN=1 ./tiny_dbt D2800181 D61F0020 D2800000 D2800540 91000400 D65F03C0

run-dispatch-slot-invalidate-midblock-example: tiny_dbt
	TINY_DBT_INVALIDATE_PC_INDEXES=3 ./tiny_dbt D2800181 D61F0020 D2800000 D2800540 91000400 D65F03C0

run-dispatch-slot-invalidate-all-example: tiny_dbt
	TINY_DBT_INVALIDATE_ALL_SLOTS=1 ./tiny_dbt D2800540 D65F03C0

run-dispatch-version-miss-cli-example: tiny_dbt
	./tiny_dbt --invalidate-dispatch D2800540 D65F03C0

run-dispatch-slot-invalidate-cli-example: tiny_dbt
	./tiny_dbt --invalidate-pc-indexes=3 D2800181 D61F0020 D2800000 D2800540 91000400 D65F03C0

run-debug-exit-example: tiny_dbt
	./tiny_dbt --debug-exit --invalidate-dispatch D2800540 D65F03C0

run-adr-example: tiny_dbt
	./tiny_dbt 10000040 D65F03C0

run-adrp-example: tiny_dbt
	./tiny_dbt 90000000 D65F03C0

run-adr-xzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 1000005F D65F03C0

run-adrp-xzr-discard-example: tiny_dbt
	./tiny_dbt --set-reg x0=7 9000001F D65F03C0

run-adr-spill-rd-example: tiny_dbt
	./tiny_dbt 1000004B 91000160 D65F03C0

run-adrp-spill-rd-example: tiny_dbt
	./tiny_dbt 9000000B 91000160 D65F03C0

run-ldur-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F8008020 D2800000 F8408020 D65F03C0

run-ldur32-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B8004020 D2800000 B8404020 D65F03C0

run-sturxzr-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F800803F D2800000 F8408020 D65F03C0

run-sturwzr-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B800403F D2800000 B8404020 D65F03C0

run-ldursw-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 F2BFFFE0 B9000420 D2800000 B9800420 D65F03C0

run-ldursw-unscaled-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 F2BFFFE0 B8004020 D2800000 B8804020 D65F03C0

run-ldur-neg-example: tiny_dbt
	./tiny_dbt D2800101 D2800540 F81F8020 D2800000 F85F8020 D65F03C0

run-ldur-neg-oob-example: tiny_dbt
	./tiny_dbt D2800001 F85F8020 D65F03C0

run-ldp-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 A9000820 D2800003 D2800004 A9401023 8B040060 D65F03C0

run-ldp32-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 29000820 29401023 8B040060 D65F03C0

run-ldpd-offset-example: tiny_dbt
	./tiny_dbt D2800001 D2801540 D2800202 9E670000 9E670041 6D010420 6D410C22 9E660040 9E660062 8B020000 D65F03C0

run-stp64-zr-source-offset-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 A9007C3F D2800003 D2800004 A9401023 8B040060 D65F03C0

run-stp32-zr-source-offset-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 29007C3F 29401023 8B040060 D65F03C0

run-ldp64-zr-discard-offset-example: tiny_dbt
	./tiny_dbt D2800001 D28000A2 D28000E3 A9000C22 D2800120 A9407C3F D65F03C0

run-ldp32-zr-discard-offset-example: tiny_dbt
	./tiny_dbt D2800001 D28000A2 D28000E3 29000C22 D2800120 29407C3F D65F03C0

run-ldrstrq-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:88776655443322110011223344556677 D2800001 3DC00020 3D800420 F9400820 D65F03C0

run-ldrstrd-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 9E670001 FD000421 FD400422 9E660040 D65F03C0

run-ldrstrs-example: tiny_dbt
	./tiny_dbt D2800001 528ACF00 72A24680 1E270001 BD000421 BD400422 1E260040 D65F03C0

run-postidx-strd-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 9E670000 FC008420 D2800000 FC5F8C21 9E660020 D65F03C0

run-preidx-ldrd-example: tiny_dbt
	./tiny_dbt D2800101 D2800540 9E670000 FC1F8020 D2800000 FC5F8C21 9E660020 D65F03C0

run-postidx-strs-example: tiny_dbt
	./tiny_dbt D2800001 528ACF00 72A24680 1E270000 BC004420 52800000 BC5FCC21 1E260020 D65F03C0

run-preidx-ldrs-example: tiny_dbt
	./tiny_dbt D2800081 528ACF00 72A24680 1E270000 BC1FC020 52800000 BC5FCC21 1E260020 D65F03C0

run-sturldur-d-unscaled-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 9E670000 FC008020 D2800000 FC408021 9E660020 D65F03C0

run-sturldur-s-unscaled-example: tiny_dbt
	./tiny_dbt D2800001 528ACF00 72A24680 1E270000 BC004020 52800000 BC404021 1E260020 D65F03C0

run-ldurq-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:88776655443322110011223344556677 D2800001 3CC00020 3C810020 F9400820 D65F03C0

run-postidx-strq-example: tiny_dbt
	./tiny_dbt --mem-write 0x20:88776655443322110011223344556677 D2800401 3CC00020 3C810420 91000020 D65F03C0

run-preidx-ldrq-example: tiny_dbt
	./tiny_dbt --mem-write 0x20:88776655443322110011223344556677 D2800201 3CC10C20 3D800420 F9400820 D65F03C0

run-ldpstpq-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:887766554433221100112233445566770102030405060708A1A2A3A4A5A6A7A8 D2800001 3DC00020 3DC00421 AD010420 AD410C22 3D801023 F9402020 D65F03C0

run-stpldpq-postpre-example: tiny_dbt
	./tiny_dbt --mem-write 0x20:887766554433221100112233445566770102030405060708A1A2A3A4A5A6A7A8 D2800401 3DC00020 3DC00421 AC810420 ADFF0C22 91000020 D65F03C0

run-neon-and16b-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0123456789ABCDEF0011223344556677FF000000000000000000000000000000 D2800001 3DC00020 3DC00421 4E211C00 3D801020 F9402020 D65F03C0

run-neon-bic16b-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0123456789ABCDEF0011223344556677FF000000000000000000000000000000 D2800001 3DC00020 3DC00421 4E611C00 3D801020 F9402020 D65F03C0

run-neon-orr16b-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0123456789ABCDEF0011223344556677FF000000000000000000000000000000 D2800001 3DC00020 3DC00421 4EA11C00 3D801020 F9402020 D65F03C0

run-neon-eor16b-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0123456789ABCDEF0011223344556677FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF D2800001 3DC00020 3DC00421 6E211C00 3D801020 F9402020 D65F03C0

run-neon-eor8b-zero-upper-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0123456789ABCDEF8899AABBCCDDEEFFFF000000000000001122334455667788 D2800001 3DC00020 3DC00421 2E211C00 3D801020 F9402420 D65F03C0

run-neon-movi16b-example: tiny_dbt
	./tiny_dbt D2800001 4F01E780 3D800420 F9400820 D65F03C0

run-neon-movi8b-example: tiny_dbt
	./tiny_dbt D2800001 0F01E780 3D800420 F9400820 D65F03C0

run-neon-movi8b-zero-upper-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:0123456789ABCDEF8899AABBCCDDEEAA D2800001 3DC00020 0F01E780 3D800420 F9400C20 D65F03C0

run-neon-movi2d-zero-example: tiny_dbt
	./tiny_dbt D2800001 6F00E400 3D800420 F9400820 D65F03C0

run-neon-movi2d-ones-example: tiny_dbt
	./tiny_dbt D2800001 6F07E7E0 3D800420 F9400820 D65F03C0

run-neon-sqrdmlah2s-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:00000040000000c000000000000000000000004000000040000000000000000001000000ffffffff78563412f0debc9a D2800001 3DC00021 3DC00422 3DC00820 2E828420 3D800C20 F9401820 F9401C22 8B020000 D65F03C0

run-neon-sqrdmlah4s-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:00000040000000c0ffffff7f000000800000004000000040ffffff7f0000008001000000ffffffff7b00000085ffffff D2800001 3DC00021 3DC00422 3DC00820 6E828420 3D801020 F9402420 D65F03C0

run-neon-sqrdmlsh2s-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:00000040000000c000000000000000000000004000000040000000000000000001000000ffffffff78563412f0debc9a D2800001 3DC00021 3DC00422 3DC00820 2EA28420 3D800C20 F9401820 F9401C22 8B020000 D65F03C0

run-neon-sqrdmlsh4s-example: tiny_dbt
	./tiny_dbt --mem-write 0x0:00000040000000c0ffffff7f000000800000004000000040ffffff7f0000008001000000ffffffff7b00000085ffffff D2800001 3DC00021 3DC00422 3DC00820 6EA28420 3D801020 F9402420 D65F03C0

run-ldrb-example: tiny_dbt
	./tiny_dbt D2800001 D2801560 39000C20 D2800000 39400C20 D65F03C0

run-ldrh-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 79000420 D2800000 79400420 D65F03C0

run-regoff32-uxtw-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE2 D2800023 B8235822 D2800000 B8635820 D65F03C0

run-regoff32-str-wzr-source-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE2 D2800023 B823583F D2800000 B8635820 D65F03C0

run-regoff32-lsl-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE2 D2800023 B8237822 D2800000 B8637820 D65F03C0

run-regoff32-sxtw-neg-example: tiny_dbt
	./tiny_dbt D2800081 D297DDE2 D2800003 D1000463 B823D822 D2800000 B863D820 D65F03C0

run-regoff64-uxtw-example: tiny_dbt
	./tiny_dbt D2800001 D2800542 D2800023 F8235822 D2800000 F8635820 D65F03C0

run-regoff64-str-xzr-source-example: tiny_dbt
	./tiny_dbt D2800001 D2800542 D2800023 F823583F D2800000 F8635820 D65F03C0

run-regoff64-lsl-example: tiny_dbt
	./tiny_dbt D2800001 D2800542 D2800023 F8237822 D2800000 F8637820 D65F03C0

run-regoff64-sxtw-neg-example: tiny_dbt
	./tiny_dbt D2800101 D2800542 D2800003 D1000463 F823D822 D2800000 F863D820 D65F03C0

run-regoff8-uxth-example: tiny_dbt
	./tiny_dbt D2800001 D2801562 D2800023 38232C22 D2800000 38632C20 D65F03C0

run-regoff8-lsl-example: tiny_dbt
	./tiny_dbt D2800001 D2801562 D2800023 38236C22 D2800000 38636C20 D65F03C0

run-regoff8-sxtw-neg-example: tiny_dbt
	./tiny_dbt D2800021 D2801562 D2800003 D1000463 3823CC22 D2800000 3863CC20 D65F03C0

run-regoff8-alt-example: tiny_dbt
	./tiny_dbt D2800001 D2801562 D2800023 38232822 D2800000 38632820 D65F03C0

run-regoff16-uxth-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE2 D2800023 78233C22 D2800000 78633C20 D65F03C0

run-regoff16-lsl-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE2 D2800023 78237C22 D2800000 78637C20 D65F03C0

run-regoff16-sxtw-neg-example: tiny_dbt
	./tiny_dbt D2800041 D297DDE2 D2800003 D1000463 7823DC22 D2800000 7863DC20 D65F03C0

run-regoff16-alt-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE2 D2800023 78233822 D2800000 78633820 D65F03C0

run-ldrsb-example: tiny_dbt
	./tiny_dbt D2800001 D2801FE0 39000420 D2800000 39C00420 D65F03C0

run-ldrsh-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 79000420 D2800000 79C00420 D65F03C0

run-ldurb-example: tiny_dbt
	./tiny_dbt D2800001 D2801560 38003020 D2800000 38403020 D65F03C0

run-ldurh-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 78002020 D2800000 78402020 D65F03C0

run-ldursb-example: tiny_dbt
	./tiny_dbt D2800001 D2801FE0 38001020 D2800000 38C01020 D65F03C0

run-ldursh-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 78002020 D2800000 78C02020 D65F03C0

run-ldursh32-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 78002020 D2800000 78802020 D65F03C0

run-ldurb-neg-example: tiny_dbt
	./tiny_dbt D2800021 D2801560 381FF020 D2800000 385FF020 D65F03C0

run-ldurh-neg-example: tiny_dbt
	./tiny_dbt D2800041 D297DDE0 781FE020 D2800000 785FE020 D65F03C0

run-ldurb-neg-oob-example: tiny_dbt
	./tiny_dbt D2800001 385FF020 D65F03C0

run-ldurh-neg-oob-example: tiny_dbt
	./tiny_dbt D2800001 785FE020 D65F03C0

run-postidx-str64-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F8008420 D2800000 F85F8020 D65F03C0

run-postidx-str64-xzr-source-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F800843F D2800000 F85F8020 D65F03C0

run-preidx-ldr64-example: tiny_dbt
	./tiny_dbt D2800101 D2800540 F81F8020 D2800000 F85F8C20 D65F03C0

run-postidx-str32-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B8004420 D2800000 B85FC020 D65F03C0

run-postidx-str32-wzr-source-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B800443F D2800000 B85FC020 D65F03C0

run-preidx-ldr32-example: tiny_dbt
	./tiny_dbt D2800081 D297DDE0 B81FC020 D2800000 B85FCC20 D65F03C0

run-postidx-strb-example: tiny_dbt
	./tiny_dbt D2800001 D2801560 38001420 D2800000 385FF020 D65F03C0

run-preidx-ldrb-example: tiny_dbt
	./tiny_dbt D2800021 D2801560 381FF020 D2800000 385FFC20 D65F03C0

run-postidx-strh-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 78002420 D2800000 785FE020 D65F03C0

run-preidx-ldrh-example: tiny_dbt
	./tiny_dbt D2800041 D297DDE0 781FE020 D2800000 785FEC20 D65F03C0

run-postidx-ldrsb-example: tiny_dbt
	./tiny_dbt D2800001 D2801FE0 39000020 D2800000 38C01420 D65F03C0

run-postidx-ldrsh-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 79000020 D2800000 78C02420 D65F03C0

run-postidx-ldrsw-example: tiny_dbt
	./tiny_dbt D2800001 D29FFFE0 F2BFFFE0 B9000020 D2800000 B8804420 D65F03C0

run-pair-post-store-pre-load64-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 A8810820 D2800000 D2800002 A9FF0820 8B020000 D65F03C0

run-pair-pre-store-post-load64-example: tiny_dbt
	./tiny_dbt D2800201 D28000A0 D28004A2 A9BF0820 D2800000 D2800002 A8C10820 8B020000 D65F03C0

run-pair-post-store-pre-load32-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 28810820 D2800000 D2800002 29FF0820 8B020000 D65F03C0

run-stp64-zr-source-postpre-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 A8817C3F D2800000 D2800002 A9FF0820 8B020000 D65F03C0

run-stp32-zr-source-postpre-example: tiny_dbt
	./tiny_dbt D2800001 D28000A0 D28004A2 28817C3F D2800000 D2800002 29FF0820 8B020000 D65F03C0

run-pair-pre-store-post-load32-example: tiny_dbt
	./tiny_dbt D2800101 D28000A0 D28004A2 29BF0820 D2800000 D2800002 28C10820 8B020000 D65F03C0

run-ldxr-stxr64-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C85F7C23 C8027C20 C85F7C20 D65F03C0

run-stxr64-fail-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C8027C20 91000040 D65F03C0

run-ldxr-stxr32-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 885F7C23 88027C20 B9400020 D65F03C0

run-ldxrb-stxrb-example: tiny_dbt
	./tiny_dbt D2800021 D2801562 085F7C23 08007C22 39400020 D65F03C0

run-stxrb-fail-example: tiny_dbt
	./tiny_dbt D2800021 D2801562 08007C22 D65F03C0

run-ldaxrb-stlxrb-example: tiny_dbt
	./tiny_dbt D2800021 D2801562 085FFC23 0800FC22 39400020 D65F03C0

run-stlxrb-fail-example: tiny_dbt
	./tiny_dbt D2800021 D2801562 0800FC22 D65F03C0

run-ldxrh-stxrh-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 485F7C23 48007C22 79400020 D65F03C0

run-stxrh-fail-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 48007C22 D65F03C0

run-ldaxr-stlxr64-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 C85FFC23 C800FC22 C8DFFC20 D65F03C0

run-stlxr64-fail-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 C800FC22 D65F03C0

run-ldxr-stxr64-sp-base-example: tiny_dbt
	./tiny_dbt D2800001 9100003F D2800540 C85F7FE3 C8027FE0 C85F7FE0 D65F03C0

run-ldaxr-stlxr64-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D2800542 C85FFFE3 C800FFE2 C8DFFFE0 D65F03C0

run-stxr64-wszr-status-discard-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C85F7C23 C81F7C20 C85F7C20 D65F03C0

run-stlxr64-wszr-status-discard-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C85FFC23 C81FFC20 C8DFFC20 D65F03C0

run-stxr64-wszr-fail-discard-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C81F7C20 C85F7C20 D65F03C0

run-stlxr64-wszr-fail-discard-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C81FFC20 C8DFFC20 D65F03C0

run-stxr64-xzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 F9000020 C85F7C23 C8027C3F C85F7C20 D65F03C0

run-stxr32-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 B9000020 885F7C23 88027C3F B9400020 D65F03C0

run-stxrb-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D2801560 39000020 085F7C23 08007C3F 39400020 D65F03C0

run-stxrh-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE0 79000020 485F7C23 48007C3F 79400020 D65F03C0

run-stlxr64-xzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D2800540 F9000020 C85FFC23 C800FC3F C8DFFC20 D65F03C0

run-stlxrb-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D2801560 39000020 085FFC23 0800FC3F 08DFFC20 D65F03C0

run-ldar-stlr64-example: tiny_dbt
	./tiny_dbt D2800021 D2800540 C89FFC20 D2800000 C8DFFC20 D65F03C0

run-ldar-stlr32-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE0 889FFC20 D2800000 88DFFC20 D65F03C0

run-ldar-stlr64-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D2800540 C89FFFE0 D2800000 C8DFFFE0 D65F03C0

run-ldar-stlr32-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D297DDE0 889FFFE0 D2800000 88DFFFE0 D65F03C0

run-ldxr64-xzr-monitor-example: tiny_dbt
	./tiny_dbt D2800001 D2800540 C85F7C3F C8027C20 C85F7C20 D65F03C0

run-ldxr32-wzr-monitor-example: tiny_dbt
	./tiny_dbt D2800001 D297DDE0 885F7C3F 88027C20 B9400020 D65F03C0

run-ldaxr64-xzr-monitor-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 C85FFC3F C800FC22 C8DFFC20 D65F03C0

run-ldar64-xzr-discard-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 F9000022 D28000E0 C8DFFC3F D65F03C0

run-ldar32-wzr-discard-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 B9000022 D28000E0 88DFFC3F D65F03C0

run-stlr64-xzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D2800540 C89FFC3F D2800000 C8DFFC20 D65F03C0

run-stlr32-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE0 889FFC3F D2800000 88DFFC20 D65F03C0

run-stlrb-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D2801560 089FFC3F D2800000 08DFFC20 D65F03C0

run-stlrh-wzr-zero-store-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE0 489FFC3F D2800000 48DFFC20 D65F03C0

run-swp64-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D2800543 F8238020 F9400024 8B040000 D65F03C0

run-swp64-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D28000E2 F90003E2 D2800543 F82383E0 F94003E4 8B040000 D65F03C0

run-ldadd64-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D28000A3 F8230020 F9400024 8B040000 D65F03C0

run-ldadd64-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D28000E2 F90003E2 D28000A3 F82303E0 F94003E4 8B040000 D65F03C0

run-ldclr64-example: tiny_dbt
	./tiny_dbt D2800021 D2800782 F9000022 D28001E3 F8231020 F9400024 8B040000 D65F03C0

run-ldeor64-example: tiny_dbt
	./tiny_dbt D2800021 D2801542 F9000022 D28001E3 F8232020 F9400024 8B040000 D65F03C0

run-ldset64-example: tiny_dbt
	./tiny_dbt D2800021 D2801402 F9000022 D28001E3 F8233020 F9400024 8B040000 D65F03C0

run-ldaddb-wrap-example: tiny_dbt
	./tiny_dbt D2800021 D2801FC2 39000022 D28000A3 38230020 39400024 8B040000 D65F03C0

run-ldsmax32-sign-example: tiny_dbt
	./tiny_dbt D2800021 D2800002 F2B00002 B9000022 D2800023 B8234020 B9400024 8B040000 D65F03C0

run-ldsmin32-sign-example: tiny_dbt
	./tiny_dbt D2800021 D29FFFE2 F2AFFFE2 B9000022 D2800003 F2B00003 B8235020 B9400024 8B040000 D65F03C0

run-ldumax32-example: tiny_dbt
	./tiny_dbt D2800021 D2800002 F2B00002 B9000022 D2800023 B8236020 B9400024 8B040000 D65F03C0

run-ldumin32-example: tiny_dbt
	./tiny_dbt D2800021 D29FFFE2 F2BFFFE2 B9000022 D29FFFE3 F2AFFFE3 B8237020 B9400024 8B040000 D65F03C0

run-ldsmaxb-al-example: tiny_dbt
	./tiny_dbt D2800021 D2801002 39000022 D2800023 38E34020 39400024 8B040000 D65F03C0

run-ldsminh-a-example: tiny_dbt
	./tiny_dbt D2800021 D28FFFE2 79000022 D2900003 78A35020 79400024 8B040000 D65F03C0

run-ldumax64-l-example: tiny_dbt
	./tiny_dbt D2800021 D2C00022 F9000022 D29FFFE3 F2BFFFE3 F8636020 F9400024 8B040000 D65F03C0

run-lduminb-al-example: tiny_dbt
	./tiny_dbt D2800021 D2801FC2 39000022 D28000A3 38E37020 39400024 8B040000 D65F03C0

run-stadd64-alias-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D28000A3 F823003F F9400020 D65F03C0

run-stclrh-alias-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 79000022 D2801E03 7823103F 79400020 D65F03C0

run-steorb-alias-example: tiny_dbt
	./tiny_dbt D2800021 D2801542 39000022 D28001E3 3823203F 39400020 D65F03C0

run-stset32-alias-example: tiny_dbt
	./tiny_dbt D2800021 D2801402 B9000022 D28001E3 B823303F B9400020 D65F03C0

run-swp64-alias-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D2800543 F823803F F9400020 D65F03C0

run-ldadd64-oob-example: tiny_dbt
	./tiny_dbt D29FFFE1 D2800023 F8230020 D65F03C0

run-cas64-success-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D2800D23 C8A27C23 F9400020 D65F03C0

run-cas64-success-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D28000E2 F90003E2 D2800D23 C8A27FE3 F94003E0 D65F03C0

run-cas64-fail-example: tiny_dbt
	./tiny_dbt D2800021 D2800002 D2800D23 D28000E4 F9000024 C8A27C23 91000040 D65F03C0

run-cas64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D2800002 D2800D23 D28000E4 F90003E4 C8A27FE3 91000040 D65F03C0

run-cas32-rtx0-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 B9000022 D2824680 88A27C20 B9400020 D65F03C0

run-casb-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800FE2 39000022 D2800843 08A27C23 39400020 D65F03C0

run-caslb-fail-example: tiny_dbt
	./tiny_dbt D2800021 D2800FE2 D2800AA4 39000024 D2800843 08A2FC23 91000040 D65F03C0

run-casah-success-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 79000022 D2824683 48E27C23 79400020 D65F03C0

run-casa64-success-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D2800D23 C8E27C23 F9400020 D65F03C0

run-casl64-fail-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 D2800124 F9000024 D2800D23 C8A2FC23 91000040 D65F03C0

run-casal32-rtx0-example: tiny_dbt
	./tiny_dbt D2800021 D297DDE2 B9000022 D2824680 88E2FC20 B9400020 D65F03C0

run-casp64-success-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 D2800123 F9000022 F9000423 D2800C84 D2800CA5 48227C24 F9400020 F9400426 8B060000 D65F03C0

run-casp64-success-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D28000E2 D2800123 F90003E2 F90007E3 D2800C84 D2800CA5 48227FE4 F94003E0 F94007E6 8B060000 D65F03C0

run-casp64-fail-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 D2800143 D2800C84 D2800CA5 D2800126 F9000022 F9000426 48227C24 91000060 D65F03C0

run-casp64-fail-sp-base-example: tiny_dbt
	./tiny_dbt D2800021 9100003F D28000E2 D2800143 D2800C84 D2800CA5 D2800126 F90003E2 F90007E6 48227FE4 91000060 D65F03C0

run-caspal64-success-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 D2800123 F9000022 F9000423 D2800C84 D2800CA5 4862FC24 F9400020 F9400426 8B060000 D65F03C0

run-caspa32-success-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 D2800123 B9000022 B9000423 D2800C84 D2800CA5 08627C24 B9400020 B9400426 8B060000 D65F03C0

run-cas64-rszr-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800002 F9000022 D2800543 C8BF7C23 F9400020 D65F03C0

run-cas64-rszr-fail-example: tiny_dbt
	./tiny_dbt D2800021 D28000E2 F9000022 D2800543 C8BF7C23 F9400020 D65F03C0

run-cas64-rtzr-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 F9000022 D2800543 C8A37C3F F9400024 8B030080 D65F03C0

run-cas64-rszr-oob-example: tiny_dbt
	./tiny_dbt D29FFFE1 D2800543 C8BF7C23 D65F03C0

run-casb-rszr-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800002 39000022 D2800543 08BF7C23 39400020 D65F03C0

run-caslb-rszr-fail-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 39000022 D28000E3 08BFFC23 39400020 D65F03C0

run-casah-rtzr-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 79000022 48E27C3F 79400020 D65F03C0

run-casal32-rtzr-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800542 B9000022 88E2FC3F B9400020 D65F03C0

run-cas32-rszr-success-example: tiny_dbt
	./tiny_dbt D2800021 D2800002 B9000022 D2800543 88BF7C23 B9400020 D65F03C0

run-casah-rszr-oob-example: tiny_dbt
	./tiny_dbt D29FFFE1 D2800543 48FF7C23 D65F03C0

clean:
	rm -f tiny_dbt tiny_dbt_runtime.o runtime_api_demo
