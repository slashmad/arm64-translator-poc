#include "tiny_nativebridge_stub.h"

#include <dlfcn.h>
#include <math.h>
#include <stdio.h>

typedef const TinyNativeBridgeCallbacks *(*GetCallbacksFn)(void);
typedef double (*CosFn)(double);

int main(int argc, char **argv) {
    const char *bridge_path = "./libtiny_nativebridge_stub.so";
    void *bridge_handle = NULL;
    void *libm_handle = NULL;
    void *cos_sym = NULL;
    CosFn cos_fn = NULL;
    GetCallbacksFn get_callbacks = NULL;
    const TinyNativeBridgeCallbacks *cb = NULL;

    if (argc > 1) {
        bridge_path = argv[1];
    }

    bridge_handle = dlopen(bridge_path, RTLD_NOW | RTLD_LOCAL);
    if (!bridge_handle) {
        fprintf(stderr, "Failed to load bridge '%s': %s\n", bridge_path, dlerror());
        return 1;
    }

    get_callbacks = (GetCallbacksFn)dlsym(bridge_handle, "tiny_nativebridge_get_callbacks");
    if (!get_callbacks) {
        fprintf(stderr, "Missing tiny_nativebridge_get_callbacks: %s\n", dlerror());
        dlclose(bridge_handle);
        return 1;
    }

    cb = get_callbacks();
    if (!cb) {
        fprintf(stderr, "Bridge returned NULL callbacks\n");
        dlclose(bridge_handle);
        return 1;
    }

    printf("NativeBridge version: %u\n", cb->version);
    if (!cb->initialize || !cb->initialize("/tmp", "arm64")) {
        fprintf(stderr, "initialize failed: %s\n", cb->get_error ? cb->get_error() : "(no error callback)");
        dlclose(bridge_handle);
        return 1;
    }

    if (!cb->load_library || !cb->get_trampoline) {
        fprintf(stderr, "callback table incomplete\n");
        dlclose(bridge_handle);
        return 1;
    }

    libm_handle = cb->load_library("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!libm_handle) {
        fprintf(stderr, "load_library failed: %s\n", cb->get_error ? cb->get_error() : "(no error)");
        dlclose(bridge_handle);
        return 1;
    }

    cos_sym = cb->get_trampoline(libm_handle, "cos", "D", 1u);
    if (!cos_sym) {
        fprintf(stderr, "get_trampoline failed: %s\n", cb->get_error ? cb->get_error() : "(no error)");
        dlclose(libm_handle);
        dlclose(bridge_handle);
        return 1;
    }
    cos_fn = (CosFn)cos_sym;
    {
        double y = cos_fn(0.0);
        double delta = fabs(y - 1.0);
        if (delta > 1e-12) {
            fprintf(stderr, "trampoline call mismatch: cos(0)=%.17g (delta=%.17g)\n", y, delta);
            dlclose(libm_handle);
            dlclose(bridge_handle);
            return 1;
        }
    }

    printf("Bridge smoke OK: loaded libm + resolved/called cos\n");

    dlclose(libm_handle);
    if (cb->terminate) {
        cb->terminate();
    }
    dlclose(bridge_handle);
    return 0;
}
