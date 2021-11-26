#include <cstdlib>
#include <stdio.h>
#include <stdarg.h>
#include "SGXSanDefs.h"
#include "Printf.h"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanCommonPoisonCheck.hpp"

// -------------------------- Run-time entry ------------------- {{{1
// exported functions
#define ASAN_REPORT_ERROR(type, is_write, size)                                        \
    extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_report_##type##size(uptr addr) \
    {                                                                                  \
        GET_CALLER_PC_BP_SP;                                                           \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);                    \
    }

ASAN_REPORT_ERROR(load, false, 1)
ASAN_REPORT_ERROR(load, false, 2)
ASAN_REPORT_ERROR(load, false, 4)
ASAN_REPORT_ERROR(load, false, 8)
ASAN_REPORT_ERROR(load, false, 16)
ASAN_REPORT_ERROR(store, true, 1)
ASAN_REPORT_ERROR(store, true, 2)
ASAN_REPORT_ERROR(store, true, 4)
ASAN_REPORT_ERROR(store, true, 8)
ASAN_REPORT_ERROR(store, true, 16)

#define ASAN_REPORT_ERROR_N(type, is_write)                                                     \
    extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_report_##type##_n(uptr addr, uptr size) \
    {                                                                                           \
        GET_CALLER_PC_BP_SP;                                                                    \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);                             \
    }

ASAN_REPORT_ERROR_N(load, false)
ASAN_REPORT_ERROR_N(store, true)

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal)
{
    if (!fatal)
        return;
    printf("Error Report:\n"
           "pc=0x%lx bp=0x%lx\n"
           "sp=0x%lx addr=0x%lx\n"
           "is_write=%d access_size=0x%lx\n",
           pc, bp, sp, addr, is_write, access_size);
    abort();
    return;
}

void PrintErrorAndAbort(const char *format, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list argptr;
    va_start(argptr, format);
    vsnprintf(buf, BUFSIZ, format, argptr);
    va_end(argptr);
    printf("[PrintErrorAndAbort] %s\n", buf);
    abort();
}