#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APK_PATH=${1:-/home/stolpee/Android/kingshot_xapk/config.arm64_v8a.apk}
LIB_ENTRY=${2:-lib/arm64-v8a/libmain.so}
PROFILE_MODE=${3:-relaxed}
LIB_BASENAME=$(basename "$LIB_ENTRY")
LIB_NAME=${LIB_BASENAME%.so}
PROFILE_DIR="$ROOT_DIR/profiles"
REPORT_DIR="$ROOT_DIR/reports"
CALLBACK_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_callbacks.txt"
STUB_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_stubs.txt"
ARGS_FILE="$PROFILE_DIR/kingshot_${LIB_NAME}_import_args.txt"
UNMAPPED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_unmapped_imports.txt"

case "$PROFILE_MODE" in
    relaxed|strict|compat)
        ;;
    *)
        echo "Invalid profile mode: $PROFILE_MODE (expected relaxed|strict|compat)" >&2
        exit 1
        ;;
esac

is_strict_mode() {
    [ "$PROFILE_MODE" = "strict" ]
}

is_compat_mode() {
    [ "$PROFILE_MODE" = "compat" ]
}

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
        atoll) echo guest_atoi_x0 ;;
        strtol|strtoll|strtoll_l) echo guest_strtol_x0_x1_x2 ;;
        strtoul|strtoull|strtoull_l) echo guest_strtoul_x0_x1_x2 ;;
        strtod|strtold_l) echo guest_strtod_x0_x1 ;;
        strtof) echo guest_strtof_x0_x1 ;;
        pow) echo guest_pow_x0_x1 ;;
        sqrt) echo guest_sqrt_x0 ;;
        cos) echo guest_cos_x0 ;;
        tan) echo guest_tan_x0 ;;
        islower) echo guest_islower_x0 ;;
        isspace) echo guest_isspace_x0 ;;
        isxdigit) echo guest_isxdigit_x0 ;;
        isupper) echo guest_isupper_x0 ;;
        toupper|towupper) echo guest_toupper_x0 ;;
        tolower|towlower) echo guest_tolower_x0 ;;
        basename) echo guest_basename_x0 ;;
        strdup) echo guest_strdup_x0 ;;
        snprintf) echo guest_snprintf_x0_x1_x2 ;;
        __vsnprintf_chk) echo guest_vsnprintf_chk_x0_x1_x4_x5 ;;
        vsnprintf) echo guest_vsnprintf_x0_x1_x2_x3 ;;
        vfprintf) echo guest_vfprintf_x0_x1_x2 ;;
        vasprintf) echo guest_vasprintf_x0_x1_x2 ;;
        posix_memalign) echo guest_posix_memalign_x0_x1_x2 ;;
        pthread_mutex_init|pthread_mutex_destroy|pthread_mutex_trylock|sigemptyset) echo ret_0 ;;
        pthread_mutexattr_init|pthread_mutexattr_destroy|pthread_mutexattr_settype) echo ret_0 ;;
        bind|connect|getsockname|sendto|socket|poll|select) echo ret_neg1 ;;
        mkdir|prctl|uname|rmdir) echo ret_0 ;;
        dup2|fork|execve|execl|pipe|eventfd|accept) echo ret_neg1 ;;
        fileno|getppid|rand|clock) echo ret_1 ;;
        srand) echo ret_0 ;;
        getaddrinfo|ioctl|lstat|rename|unlink|access|chmod|nanosleep|usleep|sleep|kill|sigaltstack|ptrace) echo ret_neg1 ;;
        gethostbyname|inet_ntoa|inet_addr|inet_ntop|strerror|realpath) echo ret_0 ;;
        inet_aton|inet_pton) echo ret_1 ;;
        localtime_r) echo ret_x1 ;;
        pthread_cond_destroy|pthread_cond_signal|pthread_cond_timedwait|pthread_equal|pthread_setname_np) echo ret_0 ;;
        sigaddset|sigfillset|signal|sigsetjmp|siglongjmp|pthread_sigmask|sigprocmask|sched_yield) echo ret_0 ;;
        strerror_r|strftime|wcrtomb|mbrtowc|mbrlen|mbsnrtowcs|mbsrtowcs|mbtowc|btowc|wctob) echo ret_1 ;;
        __ctype_get_mb_cur_max) echo ret_1 ;;
        wmemcpy|wmemmove|wmemset|strcat|strtok|strtok_r|strcoll|strcasecmp|strxfrm|wcscoll|wcsxfrm|wcsnrtombs) echo ret_x0 ;;
        strcspn|wmemcmp) echo ret_0 ;;
        wmemchr) echo ret_0 ;;
        wcslen) echo ret_0 ;;
        popen|newlocale|uselocale|localeconv|localtime|setlocale|AAssetManager_fromJava|AAssetManager_open|AAsset_open) echo ret_sp ;;
        freelocale|puts|fputs|rewind|clearerr|feof|fgetpos|fsetpos|fseeko|setvbuf) echo ret_0 ;;
        fsync|ftruncate|freeaddrinfo|__assert2|__libc_init|AAsset_close) echo ret_0 ;;
        AAsset_read|AAsset_seek|AAsset_getLength64|AAsset_openFileDescriptor64|recv|recvfrom|send|writev) echo ret_1 ;;
        shutdown|listen) echo ret_0 ;;
        eglChooseConfig|eglInitialize|eglMakeCurrent|eglTerminate|eglDestroyContext|eglDestroySurface) echo ret_1 ;;
        eglCreateContext|eglCreatePbufferSurface|eglGetCurrentContext|eglGetDisplay|glGetString) echo ret_sp ;;
        optarg|__stack_chk_guard|_ctype_) echo ret_sp ;;
        optind) echo ret_0 ;;
        __read_chk|ftello|geteuid|getpagesize|getpriority|mktime) echo ret_1 ;;
        __strncpy_chk2) echo guest_strncpy_x0_x1_x2 ;;
        __strcpy_chk) echo guest_strcpy_x0_x1 ;;
        strtold) echo guest_strtod_x0_x1 ;;
        powf) echo guest_pow_x0_x1 ;;
        isalnum|isalpha|iswalpha|iswblank|iswcntrl|iswdigit|iswlower|iswprint|iswpunct|iswspace|iswupper|iswxdigit) echo ret_0 ;;
        acos|asin|atan|atan2|sin|modf|vsprintf|perror|ferror) echo ret_0 ;;
        egl*) echo ret_0 ;;
        gl*) echo ret_0 ;;
        AAsset*) echo ret_0 ;;
        sscanf) echo guest_sscanf_x0_x1_x2 ;;
        vsscanf) echo guest_vsscanf_x0_x1_x2 ;;
        fprintf|sprintf|syslog|openlog|closelog|stat|fstat|sigaction|dl_iterate_phdr|abort|dladdr|android_set_abort_message|closedir|ferror|ftell)
            if is_strict_mode; then
                return 1
            fi
            echo ret_0
            ;;
        pthread_mutex_lock|pthread_mutex_unlock|pthread_once|pthread_key_create|pthread_key_delete|pthread_setspecific|pthread_create|pthread_join|pthread_detach|pthread_cond_wait|pthread_cond_broadcast|pthread_rwlock_wrlock|pthread_rwlock_unlock|pthread_rwlock_rdlock)
            if is_strict_mode; then
                return 1
            fi
            echo ret_0
            ;;
        close|fclose|fflush|fseek|munmap|mprotect|setsockopt|getsockopt|fcntl|remove|raise|pclose)
            if is_strict_mode; then
                return 1
            fi
            echo ret_0
            ;;
        __errno|__sF|fopen|fdopen|fgets|opendir|readdir|mmap|getenv|pthread_self)
            if is_strict_mode; then
                return 1
            fi
            echo ret_sp
            ;;
        read|write|fread|fwrite|fputc|open|lseek|lseek64|waitpid|readlink|getauxval)
            if is_strict_mode; then
                return 1
            fi
            echo ret_1
            ;;
        pthread_getspecific|getpid|gettid|sysconf|clock_gettime|gettimeofday|time|__system_property_get)
            if is_strict_mode; then
                return 1
            fi
            echo ret_1
            ;;
        syscall|__open_2|_exit|exit)
            if is_strict_mode; then
                return 1
            fi
            echo ret_neg1
            ;;
        dlopen) echo nonnull_x0 ;;
        dlsym) echo ret_sp ;;
        dlerror|__android_log_print|__android_log_assert|__android_log_write|__android_log_vprint) echo ret_x0 ;;
        *)
            if is_compat_mode; then
                case "$1" in
                    is*|to*|str*|wcs*|wmem*|mb*|mbr*|wc*|pthread_*|sig*|clock*|time*|get*|set*|open*|close*|read*|write*)
                        echo ret_0
                        return 0
                        ;;
                esac
            fi
            return 1
            ;;
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
    echo "# Profile mode: $PROFILE_MODE"
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
echo "  mode:      $PROFILE_MODE"
echo "  mapped:    $mapped_count"
echo "  unmapped:  $unmapped_count"
