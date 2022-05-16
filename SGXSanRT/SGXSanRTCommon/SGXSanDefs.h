#pragma once

#include "SGXSanInt.h"
#include "SGXSanManifest.h"
#include "SGXSanStackTrace.hpp"

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
#define ABORT_ASSERT(cond, msg)                    \
    do                                             \
    {                                              \
        if (!(cond))                               \
        {                                          \
            PRINTF("[SGXSan Error] %s \n", (msg)); \
            sgxsan_print_stack_trace();            \
            abort();                               \
        }                                          \
    } while (0)
#endif

#ifndef SGXSAN_WARNING
#define SGXSAN_WARNING(cond, msg)                    \
    do                                               \
    {                                                \
        if ((cond))                                  \
        {                                            \
            PRINTF("[SGXSan Warning] %s \n", (msg)); \
            sgxsan_print_stack_trace();              \
        }                                            \
    } while (0)
#endif

#define SGXSAN_TRACE(...) /* PRINTF */
