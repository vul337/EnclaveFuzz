#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include "SGXSanManifest.h"
#include "SGXSanDefs.h"
#include "SGXSanRTEnclave.hpp"
#include "SGXSanCommonShadowMap.hpp"

static pthread_mutex_t sgxsan_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t sgxsan_init_once = PTHREAD_ONCE_INIT;

uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
         kLowShadowBeg = 0, kLowShadowEnd = 0,
         kShadowGapBeg = 0, kShadowGapEnd = 0,
         kHighShadowBeg = 0, kHighShadowEnd = 0,
         kHighMemBeg = 0, kHighMemEnd = 0;

extern "C" void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr);

int asan_inited;

static void init_shadow_memory_out_enclave()
{
    // only use LowMem and LowShadow
    ocall_init_shadow_memory(g_enclave_base, g_enclave_size, &kLowShadowBeg, &kLowShadowEnd);
    kLowMemBeg = g_enclave_base;
    kLowMemEnd = g_enclave_base + g_enclave_size - 1;
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
    pthread_mutex_lock(&sgxsan_init_mutex);
    AsanInitInternal();
    pthread_mutex_unlock(&sgxsan_init_mutex);
}

void __attribute__((constructor)) asan_ctor()
{
    pthread_once(&sgxsan_init_once, AsanInitInternal);
}
