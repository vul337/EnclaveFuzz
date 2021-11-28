#ifndef SGXSAN_COMMON_POISON_CHECK_HPP
#define SGXSAN_COMMON_POISON_CHECK_HPP

#include "SGXSanInt.h"
#include "SGXSanCheck.h"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanAlignment.h"
#include "SGXSanCommonPoison.hpp"

static inline bool AddressIsPoisoned(uptr a, bool check_shallow_poison = false /* default don't check shallow poison */)
{
    const uptr kAccessSize = 1;
    u8 *shadow_address = (u8 *)MEM_TO_SHADOW(a);
    s8 shadow_value = *shadow_address;
    if (shadow_value)
    {
        // last_accessed_byte should <= SHADOW_GRANULARITY - 1 (i.e. 0x7)
        u8 last_accessed_byte = (a & (SHADOW_GRANULARITY - 1)) + kAccessSize - 1;
        // situation of shadow_value >= SHADOW_GRANULARITY (max positive integer for shadow byte is 0x7f) is that sgxsan's shallow poison usage
        return (check_shallow_poison ? SHADOW_GRANULARITY < shadow_value : false || last_accessed_byte >= shadow_value);
    }
    return false;
}

// Return true if we can quickly decide that the region is unpoisoned.
// We assume that a redzone is at least 16 bytes.
static inline bool QuickCheckForUnpoisonedRegion(uptr beg, uptr size)
{
    if (size == 0)
        return true;
    if (size <= 32)
        return !AddressIsPoisoned(beg) &&
               !AddressIsPoisoned(beg + size - 1) &&
               !AddressIsPoisoned(beg + size / 2);
    if (size <= 64)
        return !AddressIsPoisoned(beg) &&
               !AddressIsPoisoned(beg + size / 4) &&
               !AddressIsPoisoned(beg + size - 1) &&
               !AddressIsPoisoned(beg + 3 * size / 4) &&
               !AddressIsPoisoned(beg + size / 2);
    return false;
}

static inline bool mem_is_zero(const char *beg, uptr size, uint8_t mask = ~0)
{
    CHECK_LE(size, 1ULL << 40); // Sanity check.
    const char *end = beg + size;
    uptr *aligned_beg = (uptr *)RoundUpTo((uptr)beg, sizeof(uptr));
    uptr *aligned_end = (uptr *)RoundDownTo((uptr)end, sizeof(uptr));
    uptr all = 0;
    // Prologue.
    for (const char *mem = beg; mem < (char *)aligned_beg && mem < end; mem++)
        all |= *mem;
    // Aligned loop.
    for (; aligned_beg < aligned_end; aligned_beg++)
        all |= *aligned_beg;
    // Epilogue.
    if ((char *)aligned_end >= beg)
    {
        for (const char *mem = (char *)aligned_end; mem < end; mem++)
            all |= *mem;
    }
    return (all & mask) == 0;
}

static inline uptr __asan_region_is_poisoned(uptr beg, uptr size, bool check_shallow_poison = false)
{
    if (!size)
        return 0;
    uptr end = beg + size;
    if (!AddrIsInMem(beg))
        return beg;
    if (!AddrIsInMem(end))
        return end;

    CHECK_LT(beg, end);
    uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
    uptr aligned_e = RoundDownTo(end, SHADOW_GRANULARITY);
    uptr shadow_beg = MemToShadow(aligned_b);
    uptr shadow_end = MemToShadow(aligned_e);
    // First check the first and the last application bytes,
    // then check the SHADOW_GRANULARITY-aligned region by calling
    // mem_is_zero on the corresponding shadow.
    if (!AddressIsPoisoned(beg, check_shallow_poison) && !AddressIsPoisoned(end - 1, check_shallow_poison) &&
        (shadow_end <= shadow_beg || mem_is_zero(
                                         (const char *)shadow_beg,
                                         shadow_end - shadow_beg,
                                         (uint8_t)(check_shallow_poison ? ~0 : (~kSGXSanShadowSensitive)))))
    {
        return 0;
    }

    // The fast check failed, so we have a poisoned byte somewhere.
    // Find it slowly.
    for (; beg < end; beg++)
        if (AddressIsPoisoned(beg, check_shallow_poison))
            return beg;
    // UNREACHABLE("mem_is_zero returned false, but poisoned byte was not found");
    return 0;
}

// ElrangeCheck start
#define SGXSAN_ELRANGE_CHECK_BEG(start, is_write, size)          \
    do                                                           \
    {                                                            \
        uptr _start = (uptr)start;                               \
        uptr _end = _start + size - 1;                           \
        uptr _enclave_end = g_enclave_base + g_enclave_size - 1; \
        if (g_enclave_base <= _start && _end <= _enclave_end)    \
        {

#define SGXSAN_ELRANGE_CHECK_END \
    }                            \
    }                            \
    while (0)

#define SGXSAN_ELRANGE_DOUBLE_CHECK_BEG(start, is_write, size)                \
    do                                                                        \
    {                                                                         \
        uptr _start = (uptr)start;                                            \
        uptr _end = _start + size - 1;                                        \
        if (_start > _end)                                                    \
        {                                                                     \
            GET_CALLER_PC_BP_SP;                                              \
            ReportGenericError(pc, bp, sp, _start, is_write, size, true);     \
        }                                                                     \
        uptr _enclave_end = g_enclave_base + g_enclave_size - 1;              \
        if (_end >= g_enclave_base && _start <= _enclave_end)                 \
        {                                                                     \
            if (_start < g_enclave_base or _end > _enclave_end)               \
            {                                                                 \
                GET_CALLER_PC_BP_SP;                                          \
                ReportGenericError(pc, bp, sp, _start, is_write, size, true); \
            }

#define SGXSAN_ELRANGE_DOUBLE_CHECK_END \
    }                                   \
    }                                   \
    while (0)
// ElrangeCheck end

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

#endif