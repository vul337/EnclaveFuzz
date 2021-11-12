#ifndef POISON_CHECK_HPP
#define POISON_CHECK_HPP

#include "SGXSanInt.h"
#include "SGXSanCheck.h"
#include "ShadowMap.hpp"
#include "SGXSanAlignment.h"

static inline bool mem_is_zero(const char *beg, uptr size)
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
    return all == 0;
}

static inline bool AddressIsPoisoned(uptr a)
{
    const uptr kAccessSize = 1;
    u8 *shadow_address = (u8 *)MEM_TO_SHADOW(a);
    s8 shadow_value = *shadow_address;
    if (shadow_value)
    {
        u8 last_accessed_byte = (a & (SHADOW_GRANULARITY - 1)) + kAccessSize - 1;
        return (last_accessed_byte >= shadow_value);
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

uptr __asan_region_is_poisoned(uptr beg, uptr size);

#endif