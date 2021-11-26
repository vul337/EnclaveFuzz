#include "SGXSanDefs.h"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanCommonPoisonCheck.hpp"

#define ASAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, fatal)        \
    uptr smp = MEM_TO_SHADOW(addr);                                          \
    uptr s = size <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(smp)       \
                                        : *reinterpret_cast<u16 *>(smp);     \
    if (UNLIKELY(s))                                                         \
    {                                                                        \
        if (UNLIKELY(size >= SHADOW_GRANULARITY ||                           \
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >= \
                         (s8)s))                                             \
        {                                                                    \
            GET_CALLER_PC_BP_SP;                                             \
            ReportGenericError(pc, bp, sp, addr, is_write, size, fatal);     \
        }                                                                    \
    }

#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                       \
    extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_##type##size(uptr addr) \
    {                                                                           \
        SGXSAN_ELRANGE_CHECK_BEG(addr, is_write, size)                          \
        ASAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, true);           \
        SGXSAN_ELRANGE_CHECK_END;                                               \
    }

ASAN_MEMORY_ACCESS_CALLBACK(load, false, 1)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 2)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 4)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 8)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 16)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 1)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 2)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 4)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 8)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 16)

#define SGXSAN_MEMORY_ACCESS_CALLBACK_SIZED_BODY(addr, size, is_write) \
    SGXSAN_ELRANGE_CHECK_BEG(addr, is_write, size)                     \
    if (__asan_region_is_poisoned(addr, size))                         \
    {                                                                  \
        GET_CALLER_PC_BP_SP;                                           \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);    \
    }                                                                  \
    SGXSAN_ELRANGE_CHECK_END;

extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_loadN(uptr addr, uptr size)
{
    SGXSAN_MEMORY_ACCESS_CALLBACK_SIZED_BODY(addr, size, false);
}

extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_storeN(uptr addr, uptr size)
{
    SGXSAN_MEMORY_ACCESS_CALLBACK_SIZED_BODY(addr, size, true);
}