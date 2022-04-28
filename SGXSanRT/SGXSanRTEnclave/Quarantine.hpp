#pragma once

#include <queue>
#include <cstddef>
#include "SGXSanInt.h"
#include "ContainerAllocator.hpp"
#include "SGXSanCommonPoison.hpp"

struct QuarantineElement
{
    uptr alloc_beg;
    uptr alloc_size;
    uptr user_beg;
    uptr user_size;
};

#if (USE_SGXSAN_MALLOC)
typedef std::deque<QuarantineElement> QuarantineQueueTy;
#else
// Use SGXSan::Allocator avoid malloc-new-malloc's like infinitive loop
typedef std::deque<QuarantineElement, SGXSan::ContainerAllocator<QuarantineElement>> QuarantineQueueTy;
#endif

class QuarantineCache
{
public:
    static void init();
    static void destory();
    static void put(QuarantineElement qe);
    static void freeQuarantineElement(QuarantineElement qe);
    static void freeDirectly(QuarantineElement qe);
    static void freeOldestQuarantineElement();
    static bool empty()
    {
        return m_queue->empty();
    }

private:
    static __thread QuarantineQueueTy *m_queue;
    static __thread size_t m_quarantine_cache_used_size;
    static __thread size_t m_quarantine_cache_max_size;
};
