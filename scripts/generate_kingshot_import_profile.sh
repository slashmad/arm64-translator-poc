#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
LIB_ENTRY=${2:-lib/arm64-v8a/libmain.so}
LIB_BASENAME=$(basename "$LIB_ENTRY")
LIB_NAME=${LIB_BASENAME%.so}
PROFILE_DIR="$ROOT_DIR/profiles"
REPORT_DIR="$ROOT_DIR/reports"
CALLBACK_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_callbacks.txt"
STUB_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_stubs.txt"
ARGS_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_args.txt"
UNMAPPED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_unmapped_imports.txt"

map_callback() {
    case "$1" in
        malloc) echo guest_alloc_x0 ;;
        calloc) echo guest_calloc_x0_x1 ;;
        free) echo guest_free_x0 ;;
        realloc) echo guest_realloc_x0_x1 ;;
        memcpy|__memcpy_chk) echo guest_memcpy_x0_x1_x2 ;;
        memset|__memset_chk) echo guest_memset_x0_x1_x2 ;;
        memcmp) echo guest_memcmp_x0_x1_x2 ;;
        memmove|__memmove_chk) echo guest_memmove_x0_x1_x2 ;;
        memchr) echo guest_memchr_x0_x1_x2 ;;
        memrchr) echo guest_memrchr_x0_x1_x2 ;;
        strnlen|__strlen_chk) echo guest_strnlen_x0_x1 ;;
        strlen) echo guest_strlen_x0 ;;
        strcmp) echo guest_strcmp_x0_x1 ;;
        strncmp) echo guest_strncmp_x0_x1_x2 ;;
        strcpy) echo guest_strcpy_x0_x1 ;;
        strncpy) echo guest_strncpy_x0_x1_x2 ;;
        strchr|__strchr_chk) echo guest_strchr_x0_x1 ;;
        strrchr) echo guest_strrchr_x0_x1 ;;
        strstr) echo guest_strstr_x0_x1 ;;
        atoi) echo guest_atoi_x0 ;;
        strtol) echo guest_strtol_x0_x1_x2 ;;
        strtod) echo guest_strtod_x0_x1 ;;
        snprintf) echo guest_snprintf_x0_x1_x2 ;;
        __vsnprintf_chk) echo guest_vsnprintf_chk_x0_x1_x4_x5 ;;
        vsnprintf) echo guest_vsnprintf_x0_x1_x2_x3 ;;
        sscanf) echo guest_sscanf_x0_x1_x2 ;;
        vsscanf) echo guest_vsscanf_x0_x1_x2 ;;
        dlopen) echo nonnull_x0 ;;
        dlsym) echo ret_sp ;;
        dlerror|__android_log_print|__android_log_assert|__android_log_write|__android_log_vprint) echo ret_x0 ;;
        *) return 1 ;;
    esac
}

map_stub() {
    case "$1" in
        __cxa_atexit|__cxa_finalize|__stack_chk_fail|dlclose) echo 0 ;;
        *) return 1 ;;
    esac
}

if [ ! -f "$APK_PATH" ]; then
    echo "APK not found: $APK_PATH" >&2
    exit 1
fi

mkdir -p "$PROFILE_DIR" "$REPORT_DIR"

TMP_LIB=$(mktemp /tmp/kingshot_libmain.XXXXXX.so)
TMP_IMPORTS=$(mktemp /tmp/kingshot_imports.XXXXXX.txt)
trap 'rm -f "$TMP_LIB" "$TMP_IMPORTS"' EXIT INT TERM

unzip -p "$APK_PATH" "$LIB_ENTRY" > "$TMP_LIB"
if [ ! -s "$TMP_LIB" ]; then
    echo "Failed to extract $LIB_ENTRY from $APK_PATH" >&2
    exit 1
fi

readelf --wide -Ws "$TMP_LIB" \
    | awk '$7 == "UND" && $8 != "" {print $8}' \
    | sed 's/@.*$//' \
    | sed '/^$/d' \
    | sort -u > "$TMP_IMPORTS"

: > "$CALLBACK_FILE"
: > "$STUB_FILE"
: > "$UNMAPPED_FILE"

mapped_count=0
unmapped_count=0

while IFS= read -r sym; do
    [ -z "$sym" ] && continue

    if op=$(map_callback "$sym"); then
        printf '%s=%s\n' "$sym" "$op" >> "$CALLBACK_FILE"
        mapped_count=$((mapped_count + 1))
        continue
    fi
    if stub=$(map_stub "$sym"); then
        printf '%s=%s\n' "$sym" "$stub" >> "$STUB_FILE"
        mapped_count=$((mapped_count + 1))
        continue
    fi

    printf '%s\n' "$sym" >> "$UNMAPPED_FILE"
    unmapped_count=$((unmapped_count + 1))
done < "$TMP_IMPORTS"

sort -u -o "$CALLBACK_FILE" "$CALLBACK_FILE"
sort -u -o "$STUB_FILE" "$STUB_FILE"
sort -u -o "$UNMAPPED_FILE" "$UNMAPPED_FILE"
if [ "$unmapped_count" -eq 0 ]; then
    printf '# all imports mapped\n' > "$UNMAPPED_FILE"
fi

{
    echo "# Auto-generated import arguments for tiny_dbt"
    echo "# Source APK: $APK_PATH"
    echo "# Source entry: $LIB_ENTRY"
    while IFS= read -r spec; do
        [ -n "$spec" ] && printf '%s %s \\\n' "--elf-import-callback" "$spec"
    done < "$CALLBACK_FILE"
    while IFS= read -r spec; do
        [ -n "$spec" ] && printf '%s %s \\\n' "--elf-import-stub" "$spec"
    done < "$STUB_FILE"
} > "$ARGS_FILE"

echo "Generated Kingshot import profile:"
echo "  callbacks: $CALLBACK_FILE"
echo "  stubs:     $STUB_FILE"
echo "  args:      $ARGS_FILE"
echo "  unmapped:  $UNMAPPED_FILE"
echo "  mapped:    $mapped_count"
echo "  unmapped:  $unmapped_count"
