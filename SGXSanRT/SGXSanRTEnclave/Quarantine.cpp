#include <pthread.h>
#include <stdlib.h>
#include "Quarantine.hpp"
#include "SGXSanDefs.h"
#include "SGXSanPrintf.hpp"
#include "SGXSanManifest.h"
#include "SGXInternal.hpp"

QuarantineQueueTy *QuarantineCache::m_queue;
size_t QuarantineCache::m_quarantine_cache_used_size;
size_t QuarantineCache::m_quarantine_cache_max_size;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void QuarantineCacheInit()
{
    QuarantineCache::init();
}

void QuarantineCacheDestroy()
{
    QuarantineCache::destory();
}

void QuarantineCache::init()
{
    assert(m_queue == nullptr);
    auto p = BACKEND_MALLOC(sizeof(QuarantineQueueTy));
    UPDATE_HEAP_USAGE(p, BACKEND_MALLOC_USABLE_SZIE);
    m_queue = new (p) QuarantineQueueTy();
    assert(m_queue != nullptr);

    m_quarantine_cache_used_size = 0;
    m_quarantine_cache_max_size = get_heap_size() / 0x10;
}

void QuarantineCache::destory()
{
    assert(m_queue != nullptr);
    // free memory recorded in Quarantine, not only the struct that record Quarantine
    while (not empty())
        freeOldestQuarantineElement();
    // free struct that record Quarantine
    m_queue->~deque();
    UPDATE_HEAP_USAGE(m_queue, BACKEND_MALLOC_USABLE_SZIE, false);
    BACKEND_FREE(m_queue);
    m_queue = nullptr;

    m_quarantine_cache_used_size = 0;
    m_quarantine_cache_max_size = 0;
}

void QuarantineCache::put(QuarantineElement qe)
{
    pthread_mutex_lock(&mutex);
    if (m_queue == nullptr)
    {
        freeDirectly(qe);
        goto out;
    }

    // Consistency check
    if (m_queue->empty())
        assert(m_quarantine_cache_used_size == 0);

    // if cache can not hold this element, directly free it
    if (qe.alloc_size > m_quarantine_cache_max_size)
    {
        freeDirectly(qe);
        goto out;
    }

    // pop queue util it can hold new element
    while (UNLIKELY((!m_queue->empty()) && (m_quarantine_cache_used_size + qe.alloc_size > m_quarantine_cache_max_size)))
    {
        freeOldestQuarantineElement();
        if (m_queue->empty())
            assert(m_quarantine_cache_used_size == 0);
    }
#ifdef DUMP_OPERATION
    PRINTF("[Recycle->Quaratine] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size, qe.alloc_beg + qe.alloc_size);
#endif
    m_queue->push_back(qe);
    m_quarantine_cache_used_size += qe.alloc_size;
out:
    pthread_mutex_unlock(&mutex);
}

void QuarantineCache::freeQuarantineElement(QuarantineElement qe)
{
    UPDATE_HEAP_USAGE((void *)qe.alloc_beg, BACKEND_MALLOC_USABLE_SZIE, false);
    BACKEND_FREE(reinterpret_cast<void *>(qe.alloc_beg));
#ifdef DUMP_OPERATION
    PRINTF("[Quarantine->Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx) \n", qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size, qe.alloc_beg + qe.alloc_size);
#endif
    FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, SHADOW_GRANULARITY), kAsanHeapLeftRedzoneMagic);
    // update quarantine cache
    assert(m_quarantine_cache_used_size >= qe.alloc_size);
    m_quarantine_cache_used_size -= qe.alloc_size;
}

void QuarantineCache::freeDirectly(QuarantineElement qe)
{
    UPDATE_HEAP_USAGE((void *)qe.alloc_beg, BACKEND_MALLOC_USABLE_SZIE, false);
    BACKEND_FREE(reinterpret_cast<void *>(qe.alloc_beg));
#ifdef DUMP_OPERATION
    PRINTF("[Recycle->Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size, qe.alloc_beg + qe.alloc_size);
#endif
    FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, SHADOW_GRANULARITY), kAsanHeapLeftRedzoneMagic);
}

void QuarantineCache::freeOldestQuarantineElement()
{
    QuarantineElement front_qe = m_queue->front();
    // free and poison
    freeQuarantineElement(front_qe);
    m_queue->pop_front();
}