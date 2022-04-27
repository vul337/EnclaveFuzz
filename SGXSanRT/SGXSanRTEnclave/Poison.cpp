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

// only 'shallow-poison'/'0-unpoison' shadow which relative address is valid to access
void __sgxsan_shallow_poison_valid_shadow(uptr addr, uptr size, uint8_t value)
{
    assert(size > 0);
    if (value >= (uint8_t)0x80)
        abort();
    else
        assert((value & 0x0F) == 0);

    uptr addr_low_bits = addr % SHADOW_GRANULARITY;
    uptr complement = 0;
    if (addr_low_bits != 0)
    {
        complement = SHADOW_GRANULARITY - addr_low_bits;
        uptr shadow_addr = MEM_TO_SHADOW(addr);
        uint8_t shadow_value = *(uint8_t *)shadow_addr;
        if (shadow_value != value and shadow_value != kSGXSanSensitiveLayout and shadow_value < (uint8_t)0x80 and ((shadow_value & 0x0F) == 0 or addr_low_bits + size <= (shadow_value & 0x0F)))
        {
            *(uint8_t *)shadow_addr = (uint8_t)((value & 0xF0) + (shadow_value & 0x0F));
        }
    }
    // maybe [addr, addr+size) is all related to one shadow
    if (size > complement)
    {
        addr = addr + complement;
        size = size - complement;
        uptr shadow_addr = MEM_TO_SHADOW(addr);
        // size may not be a multiple of SHADOW_GRANULARITY, which means number of tail bytes maybe < SHADOW_GRANULARITY
        // since 8-in-1 shadow's poor expressiveness, we directly handle this end shadow-byte like other normal shadow-byte
        uptr shadow_size = (size + SHADOW_GRANULARITY - 1) / SHADOW_GRANULARITY;
        for (uptr i = 0; i < shadow_size; i++)
        {
            uint8_t shadow_value = ((uint8_t *)shadow_addr)[i];
            if (shadow_value == value or shadow_value == kSGXSanSensitiveLayout or shadow_value >= (uint8_t)0x80)
                continue;
            ((uint8_t *)shadow_addr)[i] = (uint8_t)((value & 0xF0) + (shadow_value & 0x0F));
        }
    }
}

// caller should ensure that shadow of target object is already valid(unpoisoned or shallow-poisoned)
// addr may be not aligned to `SHADOW_GRANULARITY`
void __sgxsan_shallow_poison_object(uptr addr, uptr size, uint8_t value, bool ignore_shadow_after_scope)
{
    assert(size > 0);
    if (value >= (uint8_t)0x80)
        abort();
    else
        assert((value & 0x0F) == 0);

    uptr addr_low_bits = addr % SHADOW_GRANULARITY;
    uptr complement = 0;
    if (addr_low_bits != 0)
    {
        complement = SHADOW_GRANULARITY - addr_low_bits;
        uptr shadow_addr = MEM_TO_SHADOW(addr);
        uint8_t shadow_value = *(uint8_t *)shadow_addr;
        if (shadow_value >= (uint8_t)0x80)
        {
            assert(shadow_value == 0xf8);
            if (ignore_shadow_after_scope)
            {
                *(uint8_t *)shadow_addr = value;
            }
        }
        else if (shadow_value != value and shadow_value != kSGXSanSensitiveLayout)
        {
            // maybe over-poisoned
            if ((shadow_value & 0x0F) == 0)
            {
                *(uint8_t *)shadow_addr = value;
            }
            else if (addr_low_bits + size <= (shadow_value & 0x0F))
            {
                *(uint8_t *)shadow_addr = (uint8_t)(value + (shadow_value & 0x0F));
                assert(size < complement);
            }
            else
                abort();
        }
    }
    // maybe [addr, addr+size) is all related to one shadow
    if (size > complement)
    {
        addr = addr + complement;
        size = size - complement;
        uptr shadow_addr = MEM_TO_SHADOW(addr);
        uptr shadow_size = (size + SHADOW_GRANULARITY - 1) / SHADOW_GRANULARITY;
        assert(shadow_size >= 1);
        // process middle shadow bytes
        if (shadow_size > 2)
        {
            memset((void *)shadow_addr, value, shadow_size - 1);
        }
        else if (shadow_size == 2)
        {
            *(uint8_t *)shadow_addr = value;
        }

        // now process last shadow byte
        shadow_addr += (shadow_size - 1);
        uint8_t shadow_value = *(uint8_t *)shadow_addr;
        if (shadow_value >= (uint8_t)0x80)
        {
            assert(shadow_value == 0xf8);
            if (ignore_shadow_after_scope)
            {
                *(uint8_t *)shadow_addr = value;
            }
        }
        else if (shadow_value != value and shadow_value != kSGXSanSensitiveLayout)
            *(uint8_t *)shadow_addr = (uint8_t)(value + (shadow_value & 0x0F));
    }
}
