# alpha-mapping-100

Tag: `alpha-mapping-100`
Base commit: `ba5742c`
Date: 2026-02-15

## Summary

This milestone marks full relaxed-mode Kingshot import mapping coverage in the PoC.

## Highlights

- Relaxed all-lib import coverage reached `100.00%` (`1776/1776` mapped, `0` unmapped).
- Expanded callback surface (math, errno, time/tz, handle paths).
- Added smoke stability controls (timeout + blacklist).
- Connected nativebridge demo flow to generated profile artifacts.

## Known Limitations

- Coverage/mapping does not imply gameplay compatibility.
- Non-returning entrypoints (for example `_start`-style symbols) still require blacklist handling in smoke workflows.
- NativeBridge integration remains scaffold-level, not a full Android bridge implementation.
