#ifndef QUARANTINE_HPP
#define QUARANTINE_HPP

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

class QuarantineCache
{
public:
    static void init();
    static void destory();
    static void put(QuarantineElement qe);

private:
    // Use SGXSan::Allocator avoid malloc-new-malloc's like infinitive loop
#if (!USE_SGXSAN_MALLOC)
    static __thread std::deque<QuarantineElement, SGXSan::ContainerAllocator<QuarantineElement>> *m_queue;
#else
    static __thread std::deque<QuarantineElement> *m_queue;
#endif
    static __thread size_t m_quarantine_cache_used_size;
    static __thread size_t m_quarantine_cache_max_size;
};

#endif