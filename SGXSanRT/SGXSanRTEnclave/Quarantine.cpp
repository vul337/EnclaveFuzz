#include <pthread.h>
#include <stdlib.h>
#include "Quarantine.hpp"
#include "SGXSanDefs.h"
#include "SGXSanPrintf.hpp"
#include "SGXSanManifest.h"
#include "SGXInternal.hpp"

extern __thread bool is_in_heap_operator_wrapper;

#if (USE_SGXSAN_MALLOC)
#define BACKEND_FREE free
#else
#define BACKEND_FREE dlfree
#endif

// Use SGXSan::Allocator avoid malloc-new-malloc's like infinitive loop
#if (!USE_SGXSAN_MALLOC)
__thread std::deque<QuarantineElement, SGXSan::ContainerAllocator<QuarantineElement>> *QuarantineCache::m_queue;
#else
__thread std::deque<QuarantineElement> *QuarantineCache::m_queue;
#endif
__thread size_t QuarantineCache::m_quarantine_cache_used_size;
__thread size_t QuarantineCache::m_quarantine_cache_max_size;

void QuarantineCache::init()
{
    is_in_heap_operator_wrapper = true;

    assert(m_queue == nullptr);
    m_queue = new std::deque<QuarantineElement, SGXSan::ContainerAllocator<QuarantineElement>>();
    assert(m_queue != nullptr);

    m_quarantine_cache_used_size = 0;
    m_quarantine_cache_max_size = get_heap_size() / 0x4000;

    is_in_heap_operator_wrapper = false;
}

void QuarantineCache::destory()
{
    is_in_heap_operator_wrapper = true;

    assert(m_queue != nullptr);
    delete m_queue;
    m_queue = nullptr;

    m_quarantine_cache_used_size = 0;
    m_quarantine_cache_max_size = 0;

    is_in_heap_operator_wrapper = false;
}

void QuarantineCache::put(QuarantineElement qe)
{
    uptr alignment = SHADOW_GRANULARITY;

    if (m_queue == nullptr)
    {
        BACKEND_FREE(reinterpret_cast<void *>(qe.alloc_beg));
        // PRINTF("[Recycle->Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size, qe.alloc_beg + qe.alloc_size);
        FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
        return;
    }

#if 1
    // Consistency check
    if (m_queue->empty())
    {
        assert(m_quarantine_cache_used_size == 0);
    }
#endif
    // if cache can not hold this element, directly free it
    if (qe.alloc_size > m_quarantine_cache_max_size)
    {
        BACKEND_FREE(reinterpret_cast<void *>(qe.alloc_beg));
        // PRINTF("[Recycle->Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size, qe.alloc_beg + qe.alloc_size);
        FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
        return;
    }

    // pop queue util it can hold new element
    while (UNLIKELY((!m_queue->empty()) && (m_quarantine_cache_used_size + qe.alloc_size > m_quarantine_cache_max_size)))
    {
        QuarantineElement front_qe = m_queue->front();
        // free and poison
        BACKEND_FREE(reinterpret_cast<void *>(front_qe.alloc_beg));
        // PRINTF("[Quarantine->Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx) \n", front_qe.alloc_beg, front_qe.user_beg, front_qe.user_beg + front_qe.user_size, front_qe.alloc_beg + front_qe.alloc_size);
        FastPoisonShadow(front_qe.user_beg, RoundUpTo(front_qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
        // update quarantine cache
        assert(m_quarantine_cache_used_size >= front_qe.alloc_size);
        m_quarantine_cache_used_size -= front_qe.alloc_size;
        m_queue->pop_front();
        if (m_queue->empty())
        {
            assert(m_quarantine_cache_used_size == 0);
        }
    }
    // PRINTF("[Recycle->Quaratine] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size, qe.alloc_beg + qe.alloc_size);
    m_queue->push_back(qe);
    m_quarantine_cache_used_size += qe.alloc_size;
}