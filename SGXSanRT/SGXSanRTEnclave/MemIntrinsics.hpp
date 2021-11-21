#ifndef MEM_INTRINSICS_HPP
#define MEM_INTRINSICS_HPP

#include <cstdlib>
#include "SGXSanDefs.h"
#include "SGXSanRTEnclave.hpp"
#include "ErrorReport.hpp"
#include "SGXSanCommonPoisonCheck.hpp"

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2)
{
    return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}

// We implement ACCESS_MEMORY_RANGE, ASAN_READ_RANGE,
// and ASAN_WRITE_RANGE as macro instead of function so
// that no extra frames are created, and stack trace contains
// relevant information only.
// We check all shadow bytes.
#define ACCESS_MEMORY_RANGE(offset, size, isWrite)                                                       \
    do                                                                                                   \
    {                                                                                                    \
        uptr __offset = (uptr)(offset);                                                                  \
        uptr __size = (uptr)(size);                                                                      \
        uptr __bad = 0;                                                                                  \
        if (__offset > __offset + __size)                                                                \
        {                                                                                                \
            PrintErrorAndAbort("[%s:%d] 0x%lx:%lu size overflow", __FILE__, __LINE__, __offset, __size); \
        }                                                                                                \
        if (!QuickCheckForUnpoisonedRegion(__offset, __size) &&                                          \
            (__bad = __asan_region_is_poisoned(__offset, __size)))                                       \
        {                                                                                                \
            GET_CALLER_PC_BP_SP;                                                                         \
            ReportGenericError(pc, bp, sp, __bad, isWrite, __size, false);                               \
        }                                                                                                \
    } while (0)

#define ASAN_READ_RANGE(offset, size) \
    ACCESS_MEMORY_RANGE(offset, size, false)
#define ASAN_WRITE_RANGE(offset, size) \
    ACCESS_MEMORY_RANGE(offset, size, true)

#if defined(__cplusplus)
extern "C"
{
#endif
    void *__asan_memcpy(void *to, const void *from, uptr size);
    void *__asan_memset(void *block, int c, uptr size);
    void *__asan_memmove(void *to, const void *from, uptr size);
    errno_t sgxsan_memcpy_s(void *dst, size_t sizeInBytes, const void *src, size_t count);
    errno_t sgxsan_memset_s(void *s, size_t smax, int c, size_t n);
    int sgxsan_memmove_s(void *dst, size_t sizeInBytes, const void *src, size_t count);
#if defined(__cplusplus)
}
#endif

#endif