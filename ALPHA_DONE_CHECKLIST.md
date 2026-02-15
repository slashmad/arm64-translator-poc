# Alpha Done Checklist

Use this checklist to decide if the current branch is ready for an alpha cut.

## Functional Baseline

- [ ] `make tiny_dbt` succeeds cleanly.
- [ ] `make run-fp-conversion-edge-check` passes.
- [ ] `make run-elf-symbol-index-example` passes.
- [ ] `make verify-kingshot-ci` passes.
- [ ] `make run-kingshot-mode-regression-ci` passes.
- [ ] `make run-nativebridge-skeleton-demo` passes.
- [ ] `make run-nativebridge-skeleton-runtime-smoke` passes.

## Coverage and Profiles

- [ ] Relaxed mode all-lib coverage is >= `95.00%`.
- [ ] Strict mode result is captured for regression comparison.
- [ ] Compat mode result is captured for regression comparison.
- [ ] Minimal mode result is generated and documented.

## Smoke Quality

- [ ] Smoke matrix report generated (`reports/kingshot_smoke_matrix_summary.txt`).
- [ ] Metrics report generated (`reports/kingshot_smoke_matrix_metrics.txt`).
- [ ] Exit-reason report generated (`reports/kingshot_smoke_matrix_exit_reason_summary.txt`).
- [ ] Blacklist suggestions generated (`reports/kingshot_smoke_blacklist_suggestions.txt`).

## E2E Evidence

- [ ] Batch E2E report generated (`reports/kingshot_e2e_batch_report.txt`).
- [ ] At least 3 real ARM64 libraries validated in one run.
- [ ] Known blockers captured with concrete file/symbol references.

## Release Hygiene

- [ ] Short release note added under `docs/releases/`.
- [ ] Milestone tag created and pushed.
- [ ] README updated with the latest run commands and known limits.
