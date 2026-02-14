# NativeBridge Skeleton

This folder contains a minimal, host-buildable NativeBridge-style stub.

## Targets

```sh
make -C nativebridge_skeleton
make -C nativebridge_skeleton run-demo
```

`run-demo` loads the stub `.so`, fetches its callback table, then smoke-tests `load_library/get_trampoline` by resolving `cos` from `libm.so.6`.

## Notes

- This is a scaffold only. It is not wired to the DBT runtime yet.
- The exported `NativeBridgeItf` symbol is included for future loader integration.
