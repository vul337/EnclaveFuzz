#include "Poison.hpp"
#include "SGXSanDefs.h"

void PoisonShadow(uptr addr, uptr size, u8 value)
{
    // If addr do not aligned at granularity, start posioning from RoundUpTo(addr, granularity)
    if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY)))
    {
        uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
        size -= aligned_addr - addr;
        addr = aligned_addr;
    }

    uptr remained = size & (SHADOW_GRANULARITY - 1);
    FastPoisonShadow(addr, size - remained, value);

    if (remained)
    {
        *(reinterpret_cast<u8 *>(MEM_TO_SHADOW(addr + size - remained))) = value ? value : (u8)remained;
    }
}

void __asan_set_shadow_00(uptr addr, uptr size)
{
    memset((void *)addr, 0, size);
}

void __asan_set_shadow_f1(uptr addr, uptr size)
{
    memset((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(uptr addr, uptr size)
{
    memset((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(uptr addr, uptr size)
{
    memset((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(uptr addr, uptr size)
{
    memset((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(uptr addr, uptr size)
{
    memset((void *)addr, 0xf8, size);
}

void __asan_set_shadow_fe(uptr addr, uptr size)
{
    memset((void *)addr, 0xfe, size);
}