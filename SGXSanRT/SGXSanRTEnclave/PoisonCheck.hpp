#ifndef SGXSAN_COMMON_POISON_CHECK_HPP
#define SGXSAN_COMMON_POISON_CHECK_HPP

#include "SGXSanInt.h"
#include "SGXSanCheck.h"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanAlignment.h"
#include "SGXSanCommonPoison.hpp"

#if defined(__cplusplus)
extern "C"
{
#endif
    uptr sgxsan_region_is_poisoned(uptr beg, uptr size, uint8_t mask = ~0x70);
    bool is_addr_in_elrange(uint64_t addr);
    bool is_addr_in_elrange_ex(uint64_t addr, uint64_t size);
    bool sgxsan_region_is_in_elrange_and_poisoned(uint64_t beg, uint64_t size, uint8_t mask);
#if defined(__cplusplus)
}
#endif

static inline bool AddressIsPoisoned(uptr a, uint8_t mask = ~0x70)
{
    const uptr kAccessSize = 1;
    u8 *shadow_address = (u8 *)MEM_TO_SHADOW(a);
    // situation of shadow_value >= SHADOW_GRANULARITY (max positive integer for shadow byte is 0x7f) is that sgxsan's shallow poison usage
    s8 shadow_value = (*shadow_address) & mask;
    if (shadow_value >= 0x8)
    {
        return true;
    }
    if (shadow_value)
    {
        // last_accessed_byte should <= SHADOW_GRANULARITY - 1 (i.e. 0x7)
        u8 last_accessed_byte = (a & (SHADOW_GRANULARITY - 1)) + kAccessSize - 1;

        return last_accessed_byte >= shadow_value;
    }
    return false;
}

// Return true if we can quickly decide that the region is unpoisoned.
// We assume that a redzone is at least 16 bytes.
static inline bool QuickCheckForUnpoisonedRegion(uptr beg, uptr size)
{
    if (size == 0)
        return true;
    if (size <= 32)
        return !AddressIsPoisoned(beg) &&
               !AddressIsPoisoned(beg + size - 1) &&
               !AddressIsPoisoned(beg + size / 2);
    if (size <= 64)
        return !AddressIsPoisoned(beg) &&
               !AddressIsPoisoned(beg + size / 4) &&
               !AddressIsPoisoned(beg + size - 1) &&
               !AddressIsPoisoned(beg + 3 * size / 4) &&
               !AddressIsPoisoned(beg + size / 2);
    return false;
}

static inline uint8_t mem_byte_wise_bit_or(uint8_t *beg, uptr size)
{
    CHECK_LE(size, 1ULL << 40); // Sanity check.
    uint8_t *end = beg + size;
    uint8_t all = 0;
    for (uint8_t *mem = beg; mem < end; mem++)
        all |= *mem;
    return all;
}

static inline bool mem_is_zero(uint8_t *beg, uptr size, uint8_t mask = ~0x70)
{
    uint8_t all = mem_byte_wise_bit_or((uint8_t *)beg, size);
    return (all & mask) == 0;
}

// ElrangeCheck start
#define SGXSAN_ELRANGE_CHECK_BEG(start, is_write, size)          \
    do                                                           \
    {                                                            \
        uptr _start = (uptr)start;                               \
        uptr _end = _start + size - 1;                           \
        uptr _enclave_end = g_enclave_base + g_enclave_size - 1; \
        if (g_enclave_base <= _start && _end <= _enclave_end)    \
        {

#define SGXSAN_ELRANGE_CHECK_MID                             \
    }                                                        \
    else if (_end < g_enclave_base || _enclave_end < _start) \
    {

#define SGXSAN_ELRANGE_CHECK_END \
    }                            \
    }                            \
    while (0)

#define SGXSAN_ELRANGE_DOUBLE_CHECK_BEG(start, is_write, size)                \
    do                                                                        \
    {                                                                         \
        uptr _start = (uptr)start;                                            \
        uptr _end = _start + size - 1;                                        \
        if (_start > _end)                                                    \
        {                                                                     \
            GET_CALLER_PC_BP_SP;                                              \
            ReportGenericError(pc, bp, sp, _start, is_write, size, true);     \
        }                                                                     \
        uptr _enclave_end = g_enclave_base + g_enclave_size - 1;              \
        if (_end >= g_enclave_base && _start <= _enclave_end)                 \
        {                                                                     \
            if (_start < g_enclave_base or _end > _enclave_end)               \
            {                                                                 \
                GET_CALLER_PC_BP_SP;                                          \
                ReportGenericError(pc, bp, sp, _start, is_write, size, true); \
            }

#define SGXSAN_ELRANGE_DOUBLE_CHECK_END \
    }                                   \
    }                                   \
    while (0)
// ElrangeCheck end

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2)
{
    return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}

// We implement ACCESS_MEMORY_RANGE, ASAN_READ_RANGE,
// and ASAN_WRITE_RANGE as macro instead of function so
// that no extra frames are created, and stack trace contains
// relevant information only.
// We check all shadow bytes.
#define ACCESS_MEMORY_RANGE(offset, size, isWrite)                                                       \
    do                                                                                                   \
    {                                                                                                    \
        uptr __offset = (uptr)(offset);                                                                  \
        uptr __size = (uptr)(size);                                                                      \
        uptr __bad = 0;                                                                                  \
        if (__offset > __offset + __size)                                                                \
        {                                                                                                \
            PrintErrorAndAbort("[%s:%d] 0x%lx:%lu size overflow", __FILE__, __LINE__, __offset, __size); \
        }                                                                                                \
        if (!QuickCheckForUnpoisonedRegion(__offset, __size) &&                                          \
            (__bad = sgxsan_region_is_poisoned(__offset, __size)))                                       \
        {                                                                                                \
            GET_CALLER_PC_BP_SP;                                                                         \
            ReportGenericError(pc, bp, sp, __bad, isWrite, __size, true);                                \
        }                                                                                                \
    } while (0)

#define ASAN_READ_RANGE(offset, size) \
    ACCESS_MEMORY_RANGE(offset, size, false)
#define ASAN_WRITE_RANGE(offset, size) \
    ACCESS_MEMORY_RANGE(offset, size, true)

#endif