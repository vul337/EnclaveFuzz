#ifndef SGXSAN_DEFS_H
#define SGXSAN_DEFS_H

#include "SGXSanInt.h"
#include "SGXSanManifest.h"

#define NOINLINE __attribute__((noinline))
#define INTERFACE_ATTRIBUTE __attribute__((visibility("default")))

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#ifndef GET_CALLER_PC_BP_SP
#define GET_CALLER_PC_BP_SP                      \
    uptr bp = (uptr)__builtin_frame_address(0);  \
    uptr pc = (uptr)__builtin_return_address(0); \
    uptr local_stack;                            \
    uptr sp = (uptr)&local_stack
#endif

#ifndef ABORT_ASSERT
#define ABORT_ASSERT(cond, msg)    \
    do                             \
    {                              \
        if (!(cond))               \
        {                          \
            printf("%s\n", (msg)); \
            abort();               \
        }                          \
    } while (0)
#endif

#ifndef SGXSAN_TRACE
#if (SGXSAN_DEBUG)
#define SGXSAN_TRACE printf
#else
#define SGXSAN_TRACE
#endif
#endif

#endif //SGXSAN_DEFS_H