#ifndef SGXSAN_COMMON_SHADOW_MAP_HPP
#define SGXSAN_COMMON_SHADOW_MAP_HPP

#include <stdint.h>
#include "SGXSanManifest.h"
#include "SGXSanInt.h"
#include "SGXSanCheck.h"

// there are definition on both of inside and outside enclave
extern uint64_t g_enclave_base;
extern uint64_t g_enclave_size;

#ifndef MEM_TO_SHADOW
#define MEM_TO_SHADOW(mem) ((((uint64_t)mem - g_enclave_base) >> 3) + SGXSAN_SHADOW_MAP_BASE)
#endif

#ifndef SHADOW_GRANULARITY
#define SHADOW_GRANULARITY 8
#endif

extern uint64_t kEnclaveMemBeg, kEnclaveMemEnd,
    kEnclaveShadowBeg, kEnclaveShadowEnd;

static inline bool AddrIsInMem(uptr a)
{
    return a >= kEnclaveMemBeg && a <= kEnclaveMemEnd;
}

static inline bool AddrIsInShadow(uptr a)
{
    return a >= kEnclaveShadowBeg && a <= kEnclaveShadowEnd;
}

static inline uptr MemToShadow(uptr p)
{
    CHECK(AddrIsInMem(p));
    return MEM_TO_SHADOW(p);
}

#endif // SGXSAN_COMMON_SHADOW_MAP_HPP