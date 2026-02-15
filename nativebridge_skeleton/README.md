# NativeBridge Skeleton

This folder contains a minimal, host-buildable NativeBridge-style stub.

## Targets

```sh
make -C nativebridge_skeleton
make -C nativebridge_skeleton run-demo
make -C nativebridge_skeleton run-jni-probe
```

`run-demo` loads the stub `.so`, fetches its callback table, then smoke-tests `load_library/get_trampoline` by resolving and invoking `cos` from `libm.so.6` (`cos(0) ~= 1`).
When `TINY_NB_PROFILE_CALLBACKS`/`TINY_NB_PROFILE_STUBS` are set, it also validates those profile files and prints their entry counts.
When `TINY_NB_SMOKE_APK` is set, it additionally executes `../scripts/run_kingshot_smoke.sh` (configurable via `TINY_NB_SMOKE_*` vars) for a real ELF-symbol runtime smoke.

`run-jni-probe` links against the translator runtime object and executes a tiny JNI-style return probe (`RET` with preloaded `x0=JNI_VERSION_1_6`).

## Notes

- This is still a scaffold; only the `run-jni-probe` path touches the runtime object directly.
- The exported `NativeBridgeItf` symbol is included for future loader integration.
