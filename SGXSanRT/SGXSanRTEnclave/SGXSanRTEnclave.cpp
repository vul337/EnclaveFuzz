#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include "SGXSanManifest.h"
#include "SGXSanDefs.h"
#include "SGXSanRTEnclave.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SensitivePoisoner.hpp"

static pthread_mutex_t sgxsan_init_mutex = PTHREAD_MUTEX_INITIALIZER;

uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
         kLowShadowBeg = 0, kLowShadowEnd = 0,
         kShadowGapBeg = 0, kShadowGapEnd = 0,
         kHighShadowBeg = 0, kHighShadowEnd = 0,
         kHighMemBeg = 0, kHighMemEnd = 0;

int asan_inited = 0;

static void init_shadow_memory_out_enclave()
{
    // only use LowMem and LowShadow
    ocall_init_shadow_memory(g_enclave_base, g_enclave_size, &kLowShadowBeg, &kLowShadowEnd);
    kLowMemBeg = g_enclave_base;
    kLowMemEnd = g_enclave_base + g_enclave_size - 1;
    assert(kLowShadowBeg == SGXSAN_SHADOW_MAP_BASE);
    SensitivePoisoner::collect_layout_infos();
    SensitivePoisoner::shallow_poison_senitive();
}

static void AsanInitInternal()
{
    if (LIKELY(asan_inited))
        return;

    init_shadow_memory_out_enclave();

    asan_inited = 1;
}

void AsanInitFromRtl()
{
    pthread_mutex_lock(&sgxsan_init_mutex);
    AsanInitInternal();
    pthread_mutex_unlock(&sgxsan_init_mutex);
}

void __asan_init()
{
    // sgxsdk already ensure each ctor only run once
    AsanInitInternal();
}
