#include "Quarantine.hpp"

QuarantineCache quarantine_cache;
QuarantineCache *g_quarantine_cache = &quarantine_cache;

QuarantineCache::QuarantineCache(size_t quarantine_cache_size) : quarantine_cache_max_size(quarantine_cache_size)
{
}

QuarantineCache::QuarantineCache()
{
    quarantine_cache_max_size = 1024;
}

void QuarantineCache::put(QuarantineElement qe)
{
    // Consistency check
    if (m_queue.empty())
    {
        assert(quarantine_cache_used_size == 0);
    }

    uptr alignment = SHADOW_GRANULARITY;

    // if cache can not hold this element, directly free it
    if (qe.alloc_size > quarantine_cache_max_size)
    {
        dlfree(reinterpret_cast<void *>(qe.alloc_beg));
        FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
    }

    // pop queue util it can hold new element
    while ((!m_queue.empty()) && (quarantine_cache_used_size + qe.alloc_size > quarantine_cache_max_size))
    {
        QuarantineElement front_qe = m_queue.front();
        // free and poison
        dlfree(reinterpret_cast<void *>(front_qe.alloc_beg));
        FastPoisonShadow(front_qe.user_beg, RoundUpTo(front_qe.user_size, alignment), kAsanHeapLeftRedzoneMagic);
        // update quarantine cache
        assert(quarantine_cache_used_size >= front_qe.alloc_size);
        quarantine_cache_used_size -= front_qe.alloc_size;
        m_queue.pop();
    }

    m_queue.push(qe);
    quarantine_cache_used_size += qe.alloc_size;
}