# ARM64 Translator PoC

A small dynamic binary translation (DBT) proof of concept that translates selected AArch64 instructions into x86_64 machine code and executes them with a JIT.

This project is focused on experimentation and learning. It is not a production Android NativeBridge.

## What It Does

- Decodes AArch64 instructions from hex words, raw bytecode, or ELF symbols.
- Translates supported instructions to x86_64 at runtime.
- Executes translated blocks with a small CPU state model.
- Supports a growing subset of integer, branch, memory, atomics, and FP instructions.

## Current Highlights

- Scalar FP compare and ALU: `FCMP/FCMPE`, `FADD/FSUB/FMUL/FDIV`.
- FP/GPR moves: `FMOV W<->S`, `FMOV X<->D`.
- FP/int conversions: `SCVTF`, `UCVTF`, `FCVTZS`, `FCVTZU`.
- Scalar FP memory forms: `LDR/STR S/D` (unsigned imm, post/pre-index, unscaled), plus `STP/LDP D` (signed offset).
- NEON rounding multiply-accumulate/subtract high: `SQRDMLAH/SQRDMLSH` (`2S/4S`).
- Extra sign-ext memory forms: `LDURSW (unscaled)` and `LDRSH (W)` across common immediate modes.
- Execution-driven unsupported opcode handling with optional logging.
- ELF symbol runner with out-of-range `B/BL` patching, fixed import stubs, host import callbacks, and import trace logging.

## Build

```sh
cd arm64_translator_poc
make
```

## Quick Run

Run inline opcodes:

```sh
./tiny_dbt D28000E0 91008C00 D65F03C0
```

Expected result:

```text
x0 = 42 (0x2a)
```

Run from raw code bytes:

```sh
./tiny_dbt --code-file /tmp/prog.bin
```

Run from ELF symbol:

```sh
./tiny_dbt --elf-file /tmp/libmain.so --elf-symbol JNI_OnLoad
```

## Useful CLI Options

- `--code-file <path>`: load little-endian AArch64 instruction bytes.
- `--elf-file <path> --elf-symbol <name>`: extract and run one symbol from an AArch64 ELF.
- `--elf-size <bytes>`: override symbol size when ELF reports size `0`.
- `--elf-import-stub <symbol=value>`: force specific PLT imports to return a fixed `X0` value.
- `--elf-import-callback <symbol=op>`: map PLT imports to callback ops (`ret_x0..ret_x7`, `add_x0_x1`, `sub_x0_x1`, `ret_sp`, `nonnull_x0`, `guest_alloc_x0`, `guest_free_x0`, `guest_calloc_x0_x1`, `guest_realloc_x0_x1`, `guest_memcpy_x0_x1_x2`, `guest_memset_x0_x1_x2`, `guest_memcmp_x0_x1_x2`, `guest_memmove_x0_x1_x2`, `guest_strnlen_x0_x1`, `guest_strlen_x0`, `guest_strcmp_x0_x1`, `guest_strncmp_x0_x1_x2`, `guest_strcpy_x0_x1`, `guest_strncpy_x0_x1_x2`, `guest_strchr_x0_x1`, `guest_strrchr_x0_x1`, `guest_strstr_x0_x1`, `guest_memchr_x0_x1_x2`, `guest_memrchr_x0_x1_x2`, `guest_atoi_x0`, `guest_strtol_x0_x1_x2`, `guest_snprintf_x0_x1_x2`, `guest_strtod_x0_x1`, `guest_sscanf_x0_x1_x2`, `guest_vsnprintf_x0_x1_x2_x3`, `guest_vsscanf_x0_x1_x2`, `guest_vsnprintf_chk_x0_x1_x4_x5`).
- `--elf-import-preset <name>`: apply built-in callback sets (`libc-basic`, `android-basic`).
- `--elf-import-trace <path>`: append per-symbol import patch details for ELF branch rewrites.
- `--set-reg <name=value>`: initialize registers/state, including `heap_base`, `heap_brk`, `heap_last_ptr`, `heap_last_size`.
- `--trace-state`: print compact state before/after run.
- `--mem-write <addr:hexbytes>` and `--mem-read <addr:len>`: preload/dump guest memory.
- `--log-unsupported <path>`: append unsupported opcodes that are actually executed.

Environment alternatives:

- `TINY_DBT_LOG_UNSUPPORTED`
- `TINY_DBT_TRACE_STATE`
- `TINY_DBT_INVALIDATE_BEFORE_RUN`
- `TINY_DBT_INVALIDATE_ALL_SLOTS`
- `TINY_DBT_INVALIDATE_PC_INDEXES`

## Runtime Notes

- Unsupported opcodes are translated into runtime stubs.
- An unsupported instruction only fails execution if that path is reached.
- Out-of-bounds guest memory access returns `x0 = UINT64_MAX` in this PoC.
- ELF-loaded symbols rewrite out-of-range immediate `B/BL` targets to local return stubs.
- With `--elf-import-stub`, known PLT imports can get symbol-specific fixed return values.
- With `--elf-import-callback`, known PLT imports can run host callback ops and return computed `X0`.
- With `--elf-import-preset`, common import symbols are mapped automatically (without overriding explicit `--elf-import-stub`/`--elf-import-callback` entries).
- `guest_calloc_x0_x1` allocates `x0*x1` bytes on the guest heap (16-byte aligned) and zero-fills the allocated range.
- `guest_realloc_x0_x1` resizes only the latest guest-heap allocation (PoC top-of-heap behavior).
- `guest_memcpy_x0_x1_x2`, `guest_memset_x0_x1_x2`, and `guest_memmove_x0_x1_x2` modify guest memory using `x0/x1/x2` as `dst/src-or-value/len`.
- `guest_memcmp_x0_x1_x2` compares guest memory regions and returns a signed-style diff in `x0`.
- `guest_strnlen_x0_x1` scans a guest string with a max length limit and returns length in `x0`.
- `guest_strlen_x0`, `guest_strcmp_x0_x1`, and `guest_strncmp_x0_x1_x2` provide basic C-string helpers on guest memory.
- `guest_strcpy_x0_x1`, `guest_strncpy_x0_x1_x2`, `guest_strchr_x0_x1`, `guest_strrchr_x0_x1`, `guest_strstr_x0_x1`, and `guest_memchr_x0_x1_x2` add basic copy/search helpers on guest memory.
- `guest_memrchr_x0_x1_x2`, `guest_atoi_x0`, and `guest_strtol_x0_x1_x2` add reverse-search and number parsing helpers.
- `guest_snprintf_x0_x1_x2` now supports flags, width/precision (`*` included), length modifiers (`hh/h/l/ll/j/z/t`), `%f/%e/%g`, and `%n`.
- Variadic callback arguments now continue from guest stack (starting at `SP`) after register args (`x3..x7` for `snprintf`, `x2..x7` for `sscanf`).
- `guest_vsnprintf_x0_x1_x2_x3` and `guest_vsscanf_x0_x1_x2` map guest `va_list` memory to callback argument state for variadic import hooks.
- `guest_vsnprintf_chk_x0_x1_x4_x5` handles fortified `__vsnprintf_chk(dst, size, flag, dstlen, fmt, va_list)` by reusing the variadic formatter core.
- `guest_strtod_x0_x1` parses guest strings as `double`, writes `endptr`, and mirrors result bits to both `x0` and `d0` (`v0`).
- `guest_sscanf_x0_x1_x2` provides a minimal parser for `%d/%i/%u/%x/%X/%o/%f/%e/%g/%c/%s/%[` and `%n` with output pointers in `x2..x7` and then guest stack.
- Unmapped out-of-range branches use a default local return stub and are reported as `local-ret` in trace output.
- Import mapping scans both `REL`/`RELA` PLT-style sections (`.rel[a].plt`, `.rel[a].iplt`) and `.plt/.plt.sec`-linked relocation sections.
- With `--elf-import-trace`, each import stub/callback patch is logged with symbol and branch count.

## Test Targets

You can run many regression targets via `make run-*`.

Examples:

```sh
make run-example
make run-fdivd-example
make run-fmov-ws-roundtrip-example
make run-scvtf-fcvtzs64-example
make run-ucvtf-fcvtzu64-high-example
make run-ldursw-unscaled-example
make run-ldrstrd-example
make run-postidx-strd-example
make run-neon-sqrdmlsh4s-example
make run-elf-branch-trampoline-example
make run-elf-import-stub-example
make run-import-callback-retx1-example
make run-elf-import-callback-example
make run-elf-import-trace-example
make run-elf-import-preset-example
make run-import-callback-alloc-example
make run-import-callback-free-example
make run-import-callback-alloc-free-example
make run-import-callback-calloc-example
make run-import-callback-calloc-zero-example
make run-import-callback-realloc-example
make run-import-callback-realloc-null-example
make run-import-callback-memcpy-example
make run-import-callback-memset-example
make run-import-callback-memcmp-eq-example
make run-import-callback-memcmp-ne-example
make run-import-callback-memmove-example
make run-import-callback-strnlen-example
make run-import-callback-strnlen-max-example
make run-import-callback-strlen-example
make run-import-callback-strcmp-eq-example
make run-import-callback-strcmp-ne-example
make run-import-callback-strncmp-eq-prefix-example
make run-import-callback-strncmp-ne-example
make run-import-callback-strcpy-example
make run-import-callback-strncpy-pad-example
make run-import-callback-strchr-hit-example
make run-import-callback-strchr-miss-example
make run-import-callback-strchr-nul-example
make run-import-callback-strrchr-hit-example
make run-import-callback-strrchr-miss-example
make run-import-callback-strstr-hit-example
make run-import-callback-strstr-miss-example
make run-import-callback-strstr-empty-needle-example
make run-import-callback-memchr-hit-example
make run-import-callback-memchr-miss-example
make run-import-callback-memchr-limit-example
make run-import-callback-memrchr-hit-example
make run-import-callback-memrchr-miss-example
make run-import-callback-atoi-example
make run-import-callback-atoi-neg-example
make run-import-callback-strtol-base0-example
make run-import-callback-strtol-base16-example
make run-import-callback-strtol-invalid-base-example
make run-import-callback-snprintf-mixed-example
make run-import-callback-snprintf-trunc-example
make run-import-callback-snprintf-widthprec-example
make run-import-callback-snprintf-starwidth-example
make run-import-callback-snprintf-float-n-example
make run-import-callback-snprintf-stack-varargs-example
make run-import-callback-vsnprintf-example
make run-import-callback-vsnprintf-chk-example
make run-import-callback-vsscanf-example
make run-import-callback-snprintf-inf-example
make run-import-callback-snprintf-trunc-edge-example
make run-import-callback-strtod-example
make run-import-callback-strtod-nan-example
make run-import-callback-sscanf-example
make run-import-callback-sscanf-float-n-scanset-example
make run-import-callback-sscanf-stack-varargs-example
make run-import-callback-sscanf-scanset-invert-example
make run-kingshot-import-profile
make run-kingshot-import-profile-all
make run-kingshot-smoke
make run-kingshot-smoke-matrix
make run-nativebridge-skeleton-build
make run-nativebridge-skeleton-demo
make run-unsupported-log-example
make run-elf-symbol-example
```

## Kingshot Import Profiles

Generate a profile for `kingshot` `libmain.so` imports:

```sh
make run-kingshot-import-profile
```

Generate profiles for all `arm64-v8a` libs in the APK:

```sh
make run-kingshot-import-profile-all
```

Run a smoke execution against one extracted Kingshot ELF symbol with generated import mappings:

```sh
make run-kingshot-smoke
```

Run smoke tests for the top `N` high-unmapped libs (default `5`):

```sh
make run-kingshot-smoke-matrix
```

Default `libmain` profile output:

- `profiles/kingshot_libmain_import_callbacks.txt`
- `profiles/kingshot_libmain_import_stubs.txt`
- `profiles/kingshot_libmain_import_args.txt`
- `reports/kingshot_libmain_unmapped_imports.txt`

All-lib profile output also includes:

- `reports/kingshot_all_import_profiles_summary.txt`
- `reports/kingshot_all_unmapped_imports.txt`
- `reports/kingshot_all_unmapped_top_symbols.txt`
- `reports/kingshot_all_import_coverage.txt`
- `reports/kingshot_smoke_matrix_summary.txt`

## NativeBridge Skeleton

Build the placeholder NativeBridge-style stub and loader demo:

```sh
make run-nativebridge-skeleton-build
make run-nativebridge-skeleton-demo
```

Skeleton files live under `nativebridge_skeleton/` and are intentionally minimal.

## Project Status

This is still a PoC. It does not run full Android ARM games yet.

Main missing pieces for that goal include:

- Much wider ISA coverage (especially NEON/SIMD breadth).
- Full exception/signal semantics.
- Android NativeBridge, linker/JNI, and ABI integration.
- Stronger compatibility/performance work.

## Files

- `tiny_dbt.c`: CLI frontend and ELF symbol loading.
- `tiny_dbt_runtime.h`: runtime API.
- `tiny_dbt_runtime.c`: runtime core.
- `tiny_dbt_runtime_emit.inc.c`: translator/emit logic.
- `tiny_dbt_runtime_api.inc.c`: runtime API implementation details.
- `NEXT_STEPS_ANDROID.md`: roadmap notes.

## Contributing

See `CONTRIBUTING.md`.
