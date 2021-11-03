#include "PoisonCheck.hpp"

uptr __asan_region_is_poisoned(uptr beg, uptr size)
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
    if (!AddressIsPoisoned(beg) &&
        !AddressIsPoisoned(end - 1) &&
        (shadow_end <= shadow_beg ||
         mem_is_zero((const char *)shadow_beg,
                     shadow_end - shadow_beg)))
        return 0;
    // The fast check failed, so we have a poisoned byte somewhere.
    // Find it slowly.
    for (; beg < end; beg++)
        if (AddressIsPoisoned(beg))
            return beg;
    // UNREACHABLE("mem_is_zero returned false, but poisoned byte was not found");
    return 0;
}