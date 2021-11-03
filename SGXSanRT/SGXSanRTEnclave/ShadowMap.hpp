#ifndef SHADOW_MAP_HPP
#define SHADOW_MAP_HPP

#include <stdint.h>
#include "SGXSanManifest.h"
#include "SGXSanInt.h"
#include "SGXSanCheck.h"

extern uint64_t g_enclave_base;
extern uint64_t g_enclave_size;

#ifndef MEM_TO_SHADOW
#define MEM_TO_SHADOW(mem) (((mem - g_enclave_base) >> 3) + SGXSAN_SHADOW_MAP_BASE)
#endif

#ifndef SHADOW_GRANULARITY
#define SHADOW_GRANULARITY 8
#endif

extern uint64_t kLowMemBeg, kLowMemEnd,
    kLowShadowBeg, kLowShadowEnd,
    kShadowGapBeg, kShadowGapEnd,
    kHighShadowBeg, kHighShadowEnd,
    kHighMemBeg, kHighMemEnd;

static inline bool AddrIsInLowMem(uptr a)
{
    return a <= kLowMemEnd;
}

static inline bool AddrIsInLowShadow(uptr a)
{
    return a >= kLowShadowBeg && a <= kLowShadowEnd;
}

static inline bool AddrIsInHighMem(uptr a)
{
    return kHighMemBeg && a >= kHighMemBeg && a <= kHighMemEnd;
}

static inline bool AddrIsInHighShadow(uptr a)
{
    return kHighMemBeg && a >= kHighShadowBeg && a <= kHighShadowEnd;
}

static inline bool AddrIsInShadowGap(uptr a)
{
    // In zero-based shadow mode we treat addresses near zero as addresses
    // in shadow gap as well.
    if (kLowShadowBeg == 0)
        return a <= kShadowGapEnd;
    return a >= kShadowGapBeg && a <= kShadowGapEnd;
}

static inline bool AddrIsInMem(uptr a)
{
    return AddrIsInLowMem(a) || AddrIsInHighMem(a);
}

static inline bool AddrIsInShadow(uptr a)
{
    return AddrIsInLowShadow(a) || AddrIsInHighShadow(a);
}

static inline uptr MemToShadow(uptr p)
{
    CHECK(AddrIsInMem(p));
    return MEM_TO_SHADOW(p);
}

#endif //SHADOW_MAP_HPP