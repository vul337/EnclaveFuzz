#include <assert.h>
#include "SGXSanManifest.h"
#include "SGXSanDefs.h"
#include "SGXSanRT.hpp"
#include "ShadowMap.hpp"

extern "C" void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr);

int asan_inited;

static void init_shadow_memory_out_enclave()
{
    ocall_init_shadow_memory(g_enclave_base, g_enclave_size, &kLowShadowBeg, &kHighShadowEnd);
    assert(kLowShadowBeg == SGXSAN_SHADOW_MAP_BASE);
}

static void AsanInitInternal()
{
    assert(asan_inited == 0);
    if (LIKELY(asan_inited))
        return;

    init_shadow_memory_out_enclave();

    asan_inited = 1;
}

void AsanInitFromRtl()
{
    AsanInitInternal();
}

__attribute__((constructor)) void __asan_ctor()
{
    AsanInitInternal();
}
