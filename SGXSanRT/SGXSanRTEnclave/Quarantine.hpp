#ifndef QUARANTINE_HPP
#define QUARANTINE_HPP

#include <queue>
#include <cstddef>
#include "SGXSanInt.h"
#include "ContainerAllocator.hpp"
#include "Poison.hpp"

struct QuarantineElement
{
    uptr alloc_beg;
    uptr alloc_size;
    uptr user_beg;
    uptr user_size;
};

class QuarantineCache
{
public:
    QuarantineCache();
    QuarantineCache(size_t quarantine_cache_max_size);
    void put(QuarantineElement qe);

private:
    // Use SGXSan::Allocator avoid malloc-new-malloc's like infinitive loop
#if (!USE_SGXSAN_MALLOC)
    std::queue<QuarantineElement, std::deque<QuarantineElement, SGXSan::ContainerAllocator<QuarantineElement>>> m_queue;
#else
    std::queue<QuarantineElement> m_queue;
#endif
    size_t m_quarantine_cache_used_size = 0;
    size_t m_quarantine_cache_max_size = 0;
};

extern QuarantineCache *g_quarantine_cache;

#endif