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

private:
    static void freeQuarantineElement(QuarantineElement qe);
    static void freeDirectly(QuarantineElement qe);
    static void freeOldestQuarantineElement();
    static bool empty()
    {
        return m_queue->empty();
    }

    static QuarantineQueueTy *m_queue;
    static size_t m_quarantine_cache_used_size;
    static size_t m_quarantine_cache_max_size;
};

// C Wrappers
#if defined(__cplusplus)
extern "C"
{
#endif
    // atomicity implemented by tRTS initializer about global constructor
    void QuarantineCacheInit() __attribute__((constructor));
    void QuarantineCacheDestroy() __attribute__((destructor));
#if defined(__cplusplus)
}
#endif
