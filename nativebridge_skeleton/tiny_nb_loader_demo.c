#include "tiny_nativebridge_stub.h"

#include <dlfcn.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef const TinyNativeBridgeCallbacks *(*GetCallbacksFn)(void);
typedef double (*CosFn)(double);

static size_t count_profile_specs(const char *path) {
    FILE *f = NULL;
    char line[512];
    size_t count = 0;

    if (!path || path[0] == '\0') {
        return 0;
    }
    f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        size_t i = 0;
        while (line[i] == ' ' || line[i] == '\t') {
            i++;
        }
        if (line[i] == '\0' || line[i] == '\n' || line[i] == '#') {
            continue;
        }
        count++;
    }
    fclose(f);
    return count;
}

static int maybe_run_runtime_smoke(void) {
    const char *apk_path = getenv("TINY_NB_SMOKE_APK");
    const char *lib_entry = getenv("TINY_NB_SMOKE_LIB");
    const char *symbol = getenv("TINY_NB_SMOKE_SYMBOL");
    const char *max_retries = getenv("TINY_NB_SMOKE_MAX_RETRIES");
    const char *script_path = getenv("TINY_NB_SMOKE_SCRIPT");
    char cmd[2048];
    int rc = 0;

    if (!apk_path || apk_path[0] == '\0') {
        return 0;
    }
    if (!lib_entry || lib_entry[0] == '\0') {
        lib_entry = "lib/arm64-v8a/libmain.so";
    }
    if (!symbol || symbol[0] == '\0') {
        symbol = "JNI_OnLoad";
    }
    if (!script_path || script_path[0] == '\0') {
        script_path = "../scripts/run_kingshot_smoke.sh";
    }

    if (max_retries && max_retries[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "%s '%s' '%s' '%s' '%s'", script_path, apk_path, lib_entry, symbol, max_retries);
    } else {
        snprintf(cmd, sizeof(cmd), "%s '%s' '%s' '%s'", script_path, apk_path, lib_entry, symbol);
    }

    printf("NativeBridge runtime smoke: %s\n", cmd);
    rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "Runtime smoke command failed with code %d\n", rc);
        return 1;
    }
    printf("NativeBridge runtime smoke OK: %s %s\n", lib_entry, symbol);
    return 0;
}

int main(int argc, char **argv) {
    const char *bridge_path = "./libtiny_nativebridge_stub.so";
    const char *cb_profile = getenv("TINY_NB_PROFILE_CALLBACKS");
    const char *stub_profile = getenv("TINY_NB_PROFILE_STUBS");
    void *bridge_handle = NULL;
    void *libm_handle = NULL;
    void *cos_sym = NULL;
    CosFn cos_fn = NULL;
    GetCallbacksFn get_callbacks = NULL;
    const TinyNativeBridgeCallbacks *cb = NULL;

    if (argc > 1) {
        bridge_path = argv[1];
    }
    if (cb_profile && cb_profile[0] != '\0') {
        size_t cb_count = count_profile_specs(cb_profile);
        if (cb_count == 0) {
            fprintf(stderr, "Profile callbacks missing/empty: %s\n", cb_profile);
            return 1;
        }
        printf("Profile callbacks: %s (%zu entries)\n", cb_profile, cb_count);
    }
    if (stub_profile && stub_profile[0] != '\0') {
        size_t stub_count = count_profile_specs(stub_profile);
        printf("Profile stubs: %s (%zu entries)\n", stub_profile, stub_count);
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

    if (maybe_run_runtime_smoke() != 0) {
        dlclose(libm_handle);
        if (cb->terminate) {
            cb->terminate();
        }
        dlclose(bridge_handle);
        return 1;
    }

    dlclose(libm_handle);
    if (cb->terminate) {
        cb->terminate();
    }
    dlclose(bridge_handle);
    return 0;
}
