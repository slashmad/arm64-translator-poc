# NativeBridge Skeleton

This folder contains a minimal, host-buildable NativeBridge-style stub.

## Targets

```sh
make -C nativebridge_skeleton
make -C nativebridge_skeleton run-demo
make -C nativebridge_skeleton run-jni-probe
```

`run-demo` loads the stub `.so`, fetches its callback table, then smoke-tests `load_library/get_trampoline` by resolving and invoking `cos` from `libm.so.6` (`cos(0) ~= 1`).

`run-jni-probe` links against the translator runtime object and executes a tiny JNI-style return probe (`RET` with preloaded `x0=JNI_VERSION_1_6`).

## Notes

- This is still a scaffold; only the `run-jni-probe` path touches the runtime object directly.
- The exported `NativeBridgeItf` symbol is included for future loader integration.
