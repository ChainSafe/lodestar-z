// AFL++ fuzzer harness for Zig fuzz targets.
// Adapted from Ghostty's pkg/afl++/afl.c.
//
// This file is the C "glue" that connects AFL++'s runtime to Zig-defined
// fuzz test functions. We manually expand the AFL macros (__AFL_INIT,
// __AFL_LOOP, __AFL_FUZZ_INIT, etc.) and wire up the sanitizer coverage
// symbols ourselves.

#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Disable optimization for the harness main() to ensure checks are not
// optimized out.
#pragma clang optimize off
#pragma GCC optimize("O0")

// Zig-exported entry points.
void zig_fuzz_init();
void zig_fuzz_test(unsigned char*, size_t);

// Linker-provided symbols marking the boundaries of the __sancov_guards
// section. On macOS (Mach-O), the linker uses a different naming convention
// for section boundaries than Linux (ELF).
#ifdef __APPLE__
extern uint32_t __start___sancov_guards __asm(
    "section$start$__DATA$__sancov_guards");
extern uint32_t __stop___sancov_guards __asm(
    "section$end$__DATA$__sancov_guards");
#else
extern uint32_t __start___sancov_guards;
extern uint32_t __stop___sancov_guards;
#endif

// Provided by afl-compiler-rt; initializes the guard array used by
// SanitizerCoverage's trace-pc-guard instrumentation mode.
void __sanitizer_cov_trace_pc_guard_init(uint32_t*, uint32_t*);

// Stubs for sanitizer coverage callbacks that Zig's -ffuzz references
// but AFL's runtime (afl-compiler-rt) does not provide.
__attribute__((visibility("default"))) __attribute__((
    tls_model("initial-exec"))) _Thread_local uintptr_t __sancov_lowest_stack;
void __sanitizer_cov_trace_pc_indir() {}
void __sanitizer_cov_8bit_counters_init() {}
void __sanitizer_cov_pcs_init() {}

// Manual expansion of __AFL_FUZZ_INIT().
// Enables shared-memory fuzzing: AFL++ writes test cases directly into
// shared memory instead of via stdin.
int __afl_sharedmem_fuzzing = 1;
extern __attribute__((visibility("default"))) unsigned int* __afl_fuzz_len;
extern __attribute__((visibility("default"))) unsigned char* __afl_fuzz_ptr;
unsigned char __afl_fuzz_alt[1048576];
unsigned char* __afl_fuzz_alt_ptr = __afl_fuzz_alt;

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // Tell AFL's coverage runtime about our guard section.
    __sanitizer_cov_trace_pc_guard_init(
        &__start___sancov_guards, &__stop___sancov_guards);

    // Manual expansion of __AFL_INIT() — deferred fork server mode.
    static volatile const char* _A __attribute__((used, unused));
    _A = (const char*)"##SIG_AFL_DEFER_FORKSRV##";
#ifdef __APPLE__
    __attribute__((visibility("default")))
    void _I(void) __asm__("___afl_manual_init");
#else
    __attribute__((visibility("default")))
    void _I(void) __asm__("__afl_manual_init");
#endif
    _I();

    zig_fuzz_init();

    // Manual expansion of __AFL_FUZZ_TESTCASE_BUF.
    unsigned char* buf =
        __afl_fuzz_ptr ? __afl_fuzz_ptr : __afl_fuzz_alt_ptr;

    // Manual expansion of __AFL_LOOP(UINT_MAX) — persistent mode loop.
    while (({
        static volatile const char* _B __attribute__((used, unused));
        _B = (const char*)"##SIG_AFL_PERSISTENT##";
        extern __attribute__((visibility("default"))) int __afl_connected;
#ifdef __APPLE__
        __attribute__((visibility("default")))
        int _L(unsigned int) __asm__("___afl_persistent_loop");
#else
        __attribute__((visibility("default")))
        int _L(unsigned int) __asm__("__afl_persistent_loop");
#endif
        _L(__afl_connected ? UINT_MAX : 1);
    })) {
        // Manual expansion of __AFL_FUZZ_TESTCASE_LEN.
        int len = __afl_fuzz_ptr
            ? *__afl_fuzz_len
            : (*__afl_fuzz_len =
                   read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff
                ? 0
                : *__afl_fuzz_len;

        if (len >= 0) {
            zig_fuzz_test(buf, len);
        }
    }

    return 0;
}
