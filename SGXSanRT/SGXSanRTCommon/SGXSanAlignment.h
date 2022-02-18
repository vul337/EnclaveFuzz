#ifndef SGXSAN_ALIGNMENT_H
#define SGXSAN_ALIGNMENT_H

#include "SGXSanInt.h"
#include "SGXSanCheck.h"
#include "SGXSanManifest.h"

static inline bool IsAligned(uptr a, uptr alignment)
{
    return (a & (alignment - 1)) == 0;
}

static inline bool AddrIsAlignedByGranularity(uptr addr)
{
    return IsAligned(addr, SHADOW_GRANULARITY);
}

static inline bool IsPowerOfTwo(uptr x)
{
    return (x & (x - 1)) == 0;
}

static inline uptr RoundUpTo(uptr size, uptr boundary)
{
    CHECK(IsPowerOfTwo(boundary));
    return (size + boundary - 1) & ~(boundary - 1);
}

static inline uptr RoundDownTo(uptr x, uptr boundary)
{
    return x & ~(boundary - 1);
}

#endif