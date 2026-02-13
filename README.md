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
- Execution-driven unsupported opcode handling with optional logging.
- Minimal ELF symbol runner from real AArch64 shared libraries.

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
- `--set-reg <name=value>`: initialize registers/state.
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

## Test Targets

You can run many regression targets via `make run-*`.

Examples:

```sh
make run-example
make run-fdivd-example
make run-fmov-ws-roundtrip-example
make run-scvtf-fcvtzs64-example
make run-unsupported-log-example
make run-elf-symbol-example
```

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
