#pragma once

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

#define SGXSAN_ASSERT(cond, msg)                         \
    do                                                   \
    {                                                    \
        if (!(cond))                                     \
        {                                                \
            PRINTF("[SGXSan Assert Fail] %s \n", (msg)); \
            SGXSAN_PRINT_STACK_TRACE();                  \
            abort();                                     \
        }                                                \
    } while (0)

#define SGXSAN_WARNING(cond, msg)                    \
    do                                               \
    {                                                \
        if ((cond))                                  \
        {                                            \
            PRINTF("[SGXSan Warning] %s \n", (msg)); \
            SGXSAN_PRINT_STACK_TRACE();              \
        }                                            \
    } while (0)

#if (DUMP_LOG)
#define SGXSAN_LOG PRINTF
#else
#define SGXSAN_LOG(...)
#endif
