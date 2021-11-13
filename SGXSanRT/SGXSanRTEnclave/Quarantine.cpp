#include <pthread.h>
#include "Quarantine.hpp"
#include "SGXSanDefs.h"
#include "SGXSanManifest.h"

static pthread_rwlock_t rwlock_quarantine_cache = PTHREAD_RWLOCK_INITIALIZER;

QuarantineCache quarantine_cache;
QuarantineCache *g_quarantine_cache = &quarantine_cache;

QuarantineCache::QuarantineCache(size_t quarantine_cache_max_size) : m_quarantine_cache_max_size(quarantine_cache_max_size)
{
}

QuarantineCache::QuarantineCache()
{
    m_quarantine_cache_max_size = SGXSAN_QUARANTINE_SIZE;
}

void QuarantineCache::put(QuarantineElement qe)
{
    uptr alignment = SHADOW_GRANULARITY;

#if 0
    // Consistency check
    pthread_rwlock_rdlock(&rwlock_quarantine_cache);
    if (m_queue.empty())
    {
        assert(m_quarantine_cache_used_size == 0);
    }
    pthread_rwlock_unlock(&rwlock_quarantine_cache);
#endif
    // if cache can not hold this element, directly free it
    if (qe.alloc_size > m_quarantine_cache_max_size)
    {
        dlfree(reinterpret_cast<void *>(qe.alloc_beg));
        // printf("[free] alloc_beg=0x%lx user_beg=0x%lx \n", qe.alloc_beg, qe.user_beg);
        FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
        return;
    }

    // pop queue util it can hold new element
    pthread_rwlock_wrlock(&rwlock_quarantine_cache);
    while (UNLIKELY((!m_queue.empty()) && (m_quarantine_cache_used_size + qe.alloc_size > m_quarantine_cache_max_size)))
    {
        QuarantineElement front_qe = m_queue.front();
        // free and poison
        dlfree(reinterpret_cast<void *>(front_qe.alloc_beg));
        // printf("[free for quarantine] alloc_beg=0x%lx user_beg=0x%lx \n", front_qe.alloc_beg, front_qe.user_beg);
        FastPoisonShadow(front_qe.user_beg, RoundUpTo(front_qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
        // update quarantine cache
        assert(m_quarantine_cache_used_size >= front_qe.alloc_size);
        m_quarantine_cache_used_size -= front_qe.alloc_size;
        m_queue.pop();
    }
    // printf("[quaratine] alloc_beg=0x%lx user_beg=0x%lx\n", qe.alloc_beg, qe.user_beg);
    m_queue.push(qe);
    m_quarantine_cache_used_size += qe.alloc_size;
    pthread_rwlock_unlock(&rwlock_quarantine_cache);
}