# Contributing

Thanks for contributing to this project.

This repository is an ARM64->x86_64 DBT proof of concept. The goal is correctness and clear iteration, not production polish.

## Development Setup

```sh
cd arm64_translator_poc
make
```

You should be able to run:

```sh
./tiny_dbt D28000E0 91008C00 D65F03C0
```

Expected:

```text
x0 = 42 (0x2a)
```

## Before Opening a PR

Please run at least:

```sh
make
make run-example
```

If your change touches FP, memory, dispatch, or unsupported-opcode handling, also run related `make run-*` targets and include the outputs in your PR description.

## Coding Guidelines

- Use C11 and keep builds warning-free (`-Wall -Wextra -Werror`).
- Prefer small, focused commits with clear messages.
- Avoid unrelated refactors in the same PR.
- Keep behavior changes covered by runnable examples or tests.
- Keep comments concise and useful.

## Pull Request Checklist

- Explain what changed and why.
- List commands you ran to validate the change.
- Include expected vs actual behavior when fixing a bug.
- Note known limitations or follow-up work.

## Reporting Issues

Please include:

- Exact command(s) used.
- Opcode stream or input bytes.
- Expected result and actual result.
- Platform/compiler info (OS, compiler version).

Minimal repros are preferred.

## Scope Notes

This project is still a PoC and does not provide full Android NativeBridge compatibility yet.
Large features are welcome, but incremental PRs are much easier to review and merge.
