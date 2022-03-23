#include <string.h>
#include <algorithm>
#include "Poison.hpp"
#include "SGXSanManifest.h"
#include "SGXSanCommonPoison.hpp"

static const u64 kAllocaRedzoneSize = 32UL;
static const u64 kAllocaRedzoneMask = 31UL;

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

// This is a simplified version of __asan_(un)poison_memory_region, which
// assumes that left border of region to be poisoned is properly aligned.
static void PoisonAlignedStackMemory(uptr addr, uptr size, bool do_poison)
{
    if (size == 0)
        return;
    uptr aligned_size = size & ~(SHADOW_GRANULARITY - 1);
    PoisonShadow(addr, aligned_size,
                 do_poison ? kAsanStackUseAfterScopeMagic : 0);
    if (size == aligned_size)
        return;
    s8 end_offset = (s8)(size - aligned_size);
    s8 *shadow_end = (s8 *)MemToShadow(addr + aligned_size);
    s8 end_value = *shadow_end & (s8)0x8F;
    if (do_poison)
    {
        // If possible, mark all the bytes mapping to last shadow byte as
        // unaddressable.
        if (end_value > 0 && end_value <= end_offset)
            *shadow_end = (s8)kAsanStackUseAfterScopeMagic;
    }
    else
    {
        // If necessary, mark few first bytes mapping to last shadow byte
        // as addressable
        if (end_value != 0)
            *shadow_end = std::max(end_value, end_offset);
    }
}

void __asan_poison_stack_memory(uptr addr, uptr size)
{
    PoisonAlignedStackMemory(addr, size, true);
}

void __asan_unpoison_stack_memory(uptr addr, uptr size)
{
    PoisonAlignedStackMemory(addr, size, false);
}

void __asan_alloca_poison(uptr addr, uptr size)
{
    uptr LeftRedzoneAddr = addr - kAllocaRedzoneSize;
    uptr PartialRzAddr = addr + size;
    uptr RightRzAddr = (PartialRzAddr + kAllocaRedzoneMask) & ~kAllocaRedzoneMask;
    uptr PartialRzAligned = PartialRzAddr & ~(SHADOW_GRANULARITY - 1);
    FastPoisonShadow(LeftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
    FastPoisonShadowPartialRightRedzone(
        PartialRzAligned, PartialRzAddr % SHADOW_GRANULARITY,
        RightRzAddr - PartialRzAligned, kAsanAllocaRightMagic);
    FastPoisonShadow(RightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

void __asan_allocas_unpoison(uptr top, uptr bottom)
{
    if ((!top) || (top > bottom))
        return;
    memset(reinterpret_cast<void *>(MemToShadow(top)), 0,
           (bottom - top) / SHADOW_GRANULARITY);
}

void __sgxsan_poison_valid_shadow(uptr addr, uptr size, uint8_t value)
{
    uptr shadow_addr = MEM_TO_SHADOW(addr);
    uptr shadow_size = (size + SHADOW_GRANULARITY - 1) / SHADOW_GRANULARITY;
    for (size_t i = 0; i < shadow_size; i++)
    {
        uint8_t shadow_value = ((uint8_t *)shadow_addr)[i];
        if (shadow_value == value or shadow_value == kSGXSanSensitiveLayout or shadow_value >= 0x80)
            continue;
        else if (0 < shadow_value and shadow_value < 0x8)
        {
            ((uint8_t *)shadow_addr)[i] = value | shadow_value;
        }
        else
        {
            ((uint8_t *)shadow_addr)[i] = value;
        }
    }
}
