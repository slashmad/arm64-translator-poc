#ifndef TINY_NATIVEBRIDGE_STUB_H
#define TINY_NATIVEBRIDGE_STUB_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t version;
    bool (*initialize)(const char *app_data_dir, const char *instruction_set);
    void (*terminate)(void);
    void *(*load_library)(const char *libpath, int flag);
    void *(*get_trampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    bool (*is_supported)(const char *libpath);
    const char *(*get_error)(void);
} TinyNativeBridgeCallbacks;

const TinyNativeBridgeCallbacks *tiny_nativebridge_get_callbacks(void);

#endif
