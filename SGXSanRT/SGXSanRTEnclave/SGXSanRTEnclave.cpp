#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <sgx_trts_exception.h>
#include "SGXSanManifest.h"
#include "SGXSanDefs.h"
#include "SGXSanRTEnclave.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SensitivePoisoner.hpp"
#include "Malloc.hpp"
#include "SGXSanLog.hpp"
#include "StackTrace.hpp"

struct SGXSanMMapInfo
{
    uint64_t start = 0;
    uint64_t end = 0;
    bool is_readable = false;
    bool is_writable = false;
    bool is_executable = false;
    bool is_shared = false;
    bool is_private = false;
};

pthread_rwlock_t mmap_info_rwlock = PTHREAD_RWLOCK_INITIALIZER;
size_t SGXSanMMapInfoRealCount = 0;
SGXSanMMapInfo *SGXSanMMapInfos = nullptr;

static pthread_mutex_t sgxsan_init_mutex = PTHREAD_MUTEX_INITIALIZER;

uint64_t kEnclaveMemBeg = 0, kEnclaveMemEnd = 0,
         kEnclaveShadowBeg = 0, kEnclaveShadowEnd = 0;

int asan_inited = 0;

// #PF etc. need platform (e.g. SGXv2 CPU) support conditonal exception handling
int sgxsan_exception_handler(sgx_exception_info_t *info)
{
    (void)info;
    sgxsan_print_stack_trace();
    return EXCEPTION_CONTINUE_SEARCH;
}

static void init_shadow_memory_out_enclave()
{
    // only use LowMem and LowShadow
    sgxsan_error(SGX_SUCCESS != sgxsan_ocall_init_shadow_memory(g_enclave_base, g_enclave_size, &kEnclaveShadowBeg, &kEnclaveShadowEnd), "sgxsan_ocall_init_shadow_memory failed");
    sgxsan_error(sgx_register_exception_handler(1, sgxsan_exception_handler) == nullptr, "sgx_register_exception_handler failed");
    kEnclaveMemBeg = g_enclave_base;
    kEnclaveMemEnd = g_enclave_base + g_enclave_size - 1;
    assert(kEnclaveShadowBeg == SGXSAN_SHADOW_MAP_BASE);
    // collect_layout_infos will store result to static global STL variable, however, these STL variable will initialize to 0 afer __asan_init, so if need to use it again, must collect_layout_infos again
    SensitivePoisoner::collect_layout_infos();
    SensitivePoisoner::shallow_poison_senitive();
    init_real_malloc_usable_size();
    get_mmap_infos();
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

void sgxsan_ecall_notify_update_mmap_infos()
{
    get_mmap_infos();
}

void get_mmap_infos()
{
    pthread_rwlock_wrlock(&mmap_info_rwlock);
    sgxsan_error(SGX_SUCCESS != sgxsan_ocall_get_mmap_infos((void **)&SGXSanMMapInfos, &SGXSanMMapInfoRealCount), "Fail to get mmap info\n");
    pthread_rwlock_unlock(&mmap_info_rwlock);
}

// assume SGXSanMMapInfos is sorted, and info range is [info.start, info.end]
bool _is_addr_readable(uint64_t addr, size_t length, size_t mmap_info_start_index)
{
    for (size_t i = mmap_info_start_index; i < SGXSanMMapInfoRealCount; i++)
    {
        auto &info = SGXSanMMapInfos[i];
        if (addr < info.start)
        {
            // Subsequent items will only be bigger, we can think it false early.
            return false;
        }
        else if (info.start <= addr && addr <= info.end && info.is_readable)
        {
            if (info.end < (addr + length - 1))
            {
                return _is_addr_readable(info.end + 1, addr + length - 1 - info.end, i + 1);
            }
            else
            {
                return true;
            }
        }
    }
    return false;
}

int64_t _search_closest_mmap_info_index(uint64_t addr, int64_t range_start_index, int64_t range_end_index)
{
    if (range_start_index < 0 || range_start_index > range_end_index)
        return -1;
    int64_t range_middle_index = (range_start_index + range_end_index) / 2;
    auto &info = SGXSanMMapInfos[range_middle_index];
    if (info.start <= addr and addr <= info.end)
    {
        return range_middle_index;
    }
    else if (addr < info.start)
    {
        return _search_closest_mmap_info_index(addr, range_start_index, range_middle_index - 1);
    }
    else /* addr > info.end */
    {
        return _search_closest_mmap_info_index(addr, range_middle_index + 1, range_end_index);
    }
}

bool is_pointer_readable(void *ptr, size_t element_size, int count)
{
    if (ptr == nullptr)
        return false;
    auto length = element_size * std::max(1, count);
    assert(length > 0);
    pthread_rwlock_rdlock(&mmap_info_rwlock);
    auto result = false;
    auto index = _search_closest_mmap_info_index((uint64_t)ptr, 0, SGXSanMMapInfoRealCount);
    if (index != -1)
    {
        result = _is_addr_readable((uint64_t)ptr, length, index);
    }
    pthread_rwlock_unlock(&mmap_info_rwlock);
    sgxsan_warning(result == false, "Pass non-null unreadable pointer parameter\n");
    return result;
}
