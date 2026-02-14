#define _GNU_SOURCE

#include "tiny_nativebridge_stub.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum {
    ERROR_BUF_SIZE = 256
};

static char g_last_error[ERROR_BUF_SIZE];

static void set_errorf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_last_error, sizeof(g_last_error), fmt, ap);
    va_end(ap);
}

static bool stub_initialize(const char *app_data_dir, const char *instruction_set) {
    (void)app_data_dir;
    (void)instruction_set;
    g_last_error[0] = '\0';
    return true;
}

static void stub_terminate(void) {
    g_last_error[0] = '\0';
}

static void *stub_load_library(const char *libpath, int flag) {
    void *handle = NULL;
    const char *err = NULL;

    if (!libpath || libpath[0] == '\0') {
        set_errorf("load_library: empty path");
        return NULL;
    }

    dlerror();
    handle = dlopen(libpath, flag);
    if (!handle) {
        err = dlerror();
        set_errorf("dlopen(%s) failed: %s", libpath, err ? err : "unknown");
    } else {
        g_last_error[0] = '\0';
    }
    return handle;
}

static void *stub_get_trampoline(void *handle, const char *name, const char *shorty, uint32_t len) {
    void *sym = NULL;
    const char *err = NULL;

    (void)shorty;
    (void)len;

    if (!handle || !name || name[0] == '\0') {
        set_errorf("get_trampoline: invalid handle or symbol name");
        return NULL;
    }

    dlerror();
    sym = dlsym(handle, name);
    if (!sym) {
        err = dlerror();
        set_errorf("dlsym(%s) failed: %s", name, err ? err : "unknown");
    } else {
        g_last_error[0] = '\0';
    }
    return sym;
}

static bool stub_is_supported(const char *libpath) {
    size_t len = 0;
    if (!libpath) {
        return false;
    }
    len = strlen(libpath);
    return len >= 3u && strcmp(libpath + (len - 3u), ".so") == 0;
}

static const char *stub_get_error(void) {
    return g_last_error;
}

static const TinyNativeBridgeCallbacks g_callbacks = {
    .version = 1u,
    .initialize = stub_initialize,
    .terminate = stub_terminate,
    .load_library = stub_load_library,
    .get_trampoline = stub_get_trampoline,
    .is_supported = stub_is_supported,
    .get_error = stub_get_error,
};

const TinyNativeBridgeCallbacks *tiny_nativebridge_get_callbacks(void) {
    return &g_callbacks;
}

__attribute__((visibility("default")))
const TinyNativeBridgeCallbacks *NativeBridgeItf = &g_callbacks;
