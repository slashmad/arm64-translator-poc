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
REJECTED_FILE="$REPORT_DIR/kingshot_${LIB_NAME}_rejected_import_symbols.txt"

case "$PROFILE_MODE" in
    relaxed|strict|compat|minimal)
        ;;
    *)
        echo "Invalid profile mode: $PROFILE_MODE (expected relaxed|strict|compat|minimal)" >&2
        exit 1
        ;;
esac

is_strict_mode() {
    [ "$PROFILE_MODE" = "strict" ]
}

is_compat_mode() {
    [ "$PROFILE_MODE" = "compat" ]
}

is_minimal_mode() {
    [ "$PROFILE_MODE" = "minimal" ]
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
        wcstol|wcstoll|wcstoul|wcstoull|wcstod|wcstof|wcstold) echo ret_0 ;;
        strtof) echo guest_strtof_x0_x1 ;;
        acosf) echo guest_acosf_x0 ;;
        asinf) echo guest_asinf_x0 ;;
        atan2f) echo guest_atan2f_x0_x1 ;;
        expf) echo guest_expf_x0 ;;
        logf) echo guest_logf_x0 ;;
        fmodf) echo guest_fmodf_x0_x1 ;;
        pow) echo guest_pow_x0_x1 ;;
        exp) echo guest_exp_x0 ;;
        log) echo guest_log_x0 ;;
        log10) echo guest_log10_x0 ;;
        floor) echo guest_floor_x0 ;;
        ceil) echo guest_ceil_x0 ;;
        trunc) echo guest_trunc_x0 ;;
        fmod) echo guest_fmod_x0_x1 ;;
        sin) echo guest_sin_x0 ;;
        sinh) echo guest_sinh_x0 ;;
        tanh) echo guest_tanh_x0 ;;
        lround) echo guest_lround_x0 ;;
        sqrtf) echo guest_sqrt_x0 ;;
        cosf) echo guest_cos_x0 ;;
        tanf) echo guest_tan_x0 ;;
        sinf) echo guest_sinf_x0 ;;
        sincosf) echo guest_sincosf_x0_x1_x2 ;;
        exp2f) echo guest_exp2f_x0 ;;
        log2f) echo guest_log2f_x0 ;;
        log10f) echo guest_log10f_x0 ;;
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
        bind|connect|getsockname|getpeername|socket) echo ret_neg1_enosys ;;
        send|sendto|recv|recvfrom|poll|select) echo ret_neg1_eagain ;;
        mkdir|prctl|uname|rmdir) echo ret_0 ;;
        dup2|fork|pipe|eventfd|accept|clone) echo ret_neg1_enosys ;;
        fileno|getppid|rand|clock) echo ret_1 ;;
        srand) echo ret_0 ;;
        getaddrinfo|ioctl|lstat|rename|unlink|kill|sigaltstack|ptrace|epoll_create1|epoll_ctl|epoll_wait|inotify_add_watch|inotify_init|timer_create|timer_settime|utimes|statfs|system) echo ret_neg1_enosys ;;
        access|faccessat|faccessat2|chmod|fchmod|chown|fchown|setpriority|setitimer) echo ret_neg1_eacces ;;
        open|open64|__open_2) echo guest_open_x0_x1_x2 ;;
        openat|openat64) echo guest_openat_x0_x1_x2_x3 ;;
        execv|execve|execl|pipe2|process_vm_readv) echo ret_neg1_enoent ;;
        flock) echo ret_0 ;;
        close) echo guest_close_x0 ;;
        read) echo guest_read_x0_x1_x2 ;;
        write) echo guest_write_x0_x1_x2 ;;
        nanosleep|usleep|sleep) echo ret_neg1_eintr ;;
        gethostbyname|inet_ntoa|inet_addr|inet_ntop|strerror|realpath) echo ret_0 ;;
        gai_strerror|hstrerror) echo ret_sp ;;
        inet_aton|inet_pton) echo ret_1 ;;
        getnameinfo) echo ret_0 ;;
        getopt|getopt_long) echo ret_neg1 ;;
        getcwd|gethostname|gethostbyaddr|if_indextoname|getline|tmpfile) echo ret_sp ;;
        getuid) echo ret_1 ;;
        __FD_ISSET_chk|__FD_SET_chk|__cmsg_nxthdr|__google_potentially_blocking_region_begin|__google_potentially_blocking_region_end) echo ret_0 ;;
        __get_h_errno) echo guest_errno_ptr ;;
        __system_property_find) echo ret_sp ;;
        __umask_chk) echo ret_neg1_eperm ;;
        localtime_r) echo ret_x1 ;;
        ctime) echo guest_ctime_x0 ;;
        gmtime) echo guest_gmtime_x0 ;;
        tzset) echo guest_tzset_0 ;;
        pthread_cond_destroy|pthread_cond_signal|pthread_cond_timedwait|pthread_equal|pthread_setname_np) echo ret_0 ;;
        pthread_getschedparam|pthread_attr_init|pthread_attr_setschedparam|pthread_attr_setschedpolicy|pthread_cond_init) echo ret_0 ;;
        pthread_condattr_setclock|pthread_condattr_init|pthread_condattr_destroy|pthread_exit) echo ret_0 ;;
        sem_wait|sem_post|sem_init|sem_destroy|sched_getparam|sched_getscheduler|sigismember) echo ret_0 ;;
        sendmsg|recvmsg) echo ret_neg1_eagain ;;
        regcomp|regexec|scandir|nftw|qsort|alphasort) echo ret_0 ;;
        printf|swprintf|fscanf|getc|fgetc|putchar) echo ret_1 ;;
        strncat) echo ret_x0 ;;
        strncasecmp) echo ret_0 ;;
        wctype) echo ret_1 ;;
        ungetc) echo ret_x0 ;;
        gmtime_r) echo ret_x1 ;;
        frexp|ldexp|difftime|cosh) echo ret_0 ;;
        sigaddset|sigfillset|signal|sigsetjmp|siglongjmp|pthread_sigmask|sigprocmask|sched_yield) echo ret_0 ;;
        strerror_r|strftime|wcrtomb|mbrtowc|mbrlen|mbsnrtowcs|mbsrtowcs|mbtowc|btowc|wctob) echo ret_1 ;;
        __ctype_get_mb_cur_max) echo ret_1 ;;
        wmemcpy|wmemmove|wmemset|strcat|strtok|strtok_r|strcoll|strcasecmp|strxfrm|wcscoll|wcsxfrm|wcsnrtombs|strcasestr|strpbrk|strlcpy) echo ret_x0 ;;
        strcspn|wmemcmp) echo ret_0 ;;
        wmemchr) echo ret_0 ;;
        wcsftime|strftime_l) echo ret_1 ;;
        wcslen) echo ret_0 ;;
        popen|newlocale|uselocale|localeconv|localtime|setlocale|AAssetManager_fromJava|AAssetManager_open|AAsset_open|tzname|environ) echo ret_sp ;;
        daylight) echo guest_daylight_ptr ;;
        timezone) echo guest_timezone_ptr ;;
        freelocale|puts|fputs|rewind|clearerr|feof|fgetpos|fsetpos|fseeko|setvbuf) echo ret_0 ;;
        fsync|ftruncate|freeaddrinfo|__assert2|__libc_init|AAsset_close) echo ret_0 ;;
        deflateInit_|deflateInit2_|deflateEnd|inflateInit_|inflateEnd) echo ret_0 ;;
        deflate|inflate) echo ret_1 ;;
        ZSTD_trace_decompress_begin|ZSTD_trace_decompress_end|zError) echo ret_0 ;;
        AAsset_read|AAsset_seek|AAsset_getLength64|AAsset_openFileDescriptor64|writev) echo ret_1 ;;
        shutdown|listen) echo ret_0 ;;
        eglChooseConfig|eglInitialize|eglMakeCurrent|eglTerminate|eglDestroyContext|eglDestroySurface) echo ret_1 ;;
        eglCreateContext|eglCreatePbufferSurface|eglGetCurrentContext|eglGetDisplay|glGetString) echo guest_handle_x0 ;;
        optarg|__stack_chk_guard|_ctype_) echo ret_sp ;;
        optind) echo ret_0 ;;
        __read_chk|ftello|geteuid|getpagesize|getpriority|mktime) echo ret_1 ;;
        __strncpy_chk2) echo guest_strncpy_x0_x1_x2 ;;
        __strncat_chk) echo ret_x0 ;;
        __strcpy_chk) echo guest_strcpy_x0_x1 ;;
        strtold) echo guest_strtod_x0_x1 ;;
        powf) echo guest_pow_x0_x1 ;;
        slCreateEngine) echo guest_handle_x0 ;;
        SL_IID_*) echo guest_handle_x0 ;;
        _Znwm|_Znam) echo guest_alloc_x0 ;;
        _ZdlPv|_ZdaPv|_ZdlPvm|_ZdaPvm) echo guest_free_x0 ;;
        __cxa_allocate_exception) echo guest_alloc_x0 ;;
        __cxa_free_exception) echo guest_free_x0 ;;
        __cxa_begin_catch) echo ret_x0 ;;
        __cxa_end_catch|__cxa_thread_atexit_impl|__gxx_personality_v0) echo ret_0 ;;
        __cxa_throw|_Unwind_Resume|_ZSt9terminatev) echo ret_neg1_eintr ;;
        _ZTI*|_ZTV*) echo ret_sp ;;
        _ZN*) echo ret_0 ;;
        isalnum|isalpha|iswalpha|iswblank|iswcntrl|iswdigit|iswlower|iswprint|iswpunct|iswspace|iswupper|iswxdigit) echo ret_0 ;;
        iscntrl|isdigit|isdigit_l|isgraph|islower_l|isprint|ispunct|isupper_l|isxdigit_l|iswctype|iswlower_l) echo ret_0 ;;
        acos|asin|atan|atan2|sin|modf|vsprintf|perror|ferror|abs|div|ldiv|random) echo ret_0 ;;
        alarm) echo ret_0 ;;
        mkstemp|pread|pread64) echo ret_1 ;;
        mremap|memmem) echo ret_sp ;;
        srandom) echo ret_0 ;;
        egl*) echo ret_0 ;;
        gl*) echo ret_0 ;;
        AAsset*) echo ret_0 ;;
        sscanf) echo guest_sscanf_x0_x1_x2 ;;
        vsscanf) echo guest_vsscanf_x0_x1_x2 ;;
        fprintf|sprintf|syslog|openlog|closelog|stat|fstat|sigaction|dl_iterate_phdr|abort|dladdr|android_set_abort_message|closedir|ferror|ftell)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_0
            ;;
        pthread_mutex_lock|pthread_mutex_unlock|pthread_once|pthread_key_create|pthread_key_delete|pthread_setspecific|pthread_create|pthread_join|pthread_detach|pthread_cond_wait|pthread_cond_broadcast|pthread_rwlock_wrlock|pthread_rwlock_unlock|pthread_rwlock_rdlock)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_0
            ;;
        fclose|fflush|fseek|munmap|mprotect|setsockopt|getsockopt|fcntl|remove|raise|pclose)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_0
            ;;
        __sF|fopen|fdopen|fgets|opendir|readdir|mmap|getenv|pthread_self)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_sp
            ;;
        fread|fwrite|fputc|lseek|lseek64|waitpid|readlink|getauxval)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_1
            ;;
        pthread_getspecific|getpid|gettid|sysconf|clock_gettime|gettimeofday|time|__system_property_get)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_1
            ;;
        syscall|__open_2)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_neg1_enosys
            ;;
        _exit|exit)
            if is_strict_mode || is_minimal_mode; then
                return 1
            fi
            echo ret_neg1_eintr
            ;;
        dlopen) echo nonnull_x0 ;;
        dlsym) echo ret_sp ;;
        __errno|__errno_location) echo guest_errno_ptr ;;
        dlerror|__android_log_print|__android_log_assert|__android_log_write|__android_log_vprint|__android_log_buf_write) echo ret_x0 ;;
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
        __cxa_*|__gxx_personality_v0|_Unwind_Resume|_ZSt9terminatev) echo 0 ;;
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

: > "$REJECTED_FILE"

LC_ALL=C readelf --wide -Ws "$TMP_LIB" \
    | LC_ALL=C awk -v rejected="$REJECTED_FILE" '
        function printable_ascii(s, t) {
            t = s;
            gsub(/[ -~]/, "", t);
            return length(t) == 0;
        }
        function symbolish_ascii(s) {
            return s ~ /^[A-Za-z_.$?][A-Za-z0-9_.$?@]*$/;
        }
        $7 == "UND" && $8 != "" {
            sym = $8;
            sub(/@.*/, "", sym);
            if (sym == "") {
                next;
            }
            if (printable_ascii(sym) && symbolish_ascii(sym)) {
                print sym;
            } else {
                print sym >> rejected;
            }
        }
    ' \
    | sort -u > "$TMP_IMPORTS"

sort -u -o "$REJECTED_FILE" "$REJECTED_FILE"

: > "$CALLBACK_FILE"
: > "$STUB_FILE"
: > "$UNMAPPED_FILE"

mapped_count=0
unmapped_count=0
rejected_count=0

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
rejected_count=$(grep -cve '^[[:space:]]*$' "$REJECTED_FILE" || true)

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
echo "  rejected:  $REJECTED_FILE"
echo "  mode:      $PROFILE_MODE"
echo "  mapped:    $mapped_count"
echo "  unmapped:  $unmapped_count"
echo "  rejected:  $rejected_count"
