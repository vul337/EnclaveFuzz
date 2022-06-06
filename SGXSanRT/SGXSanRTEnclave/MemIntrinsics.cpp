#include <string.h>
#include <assert.h>
#include <mbusafecrt.h>
#include <cstdlib>
#include "SGXSanDefs.h"
#include "SGXSanRTEnclave.hpp"
#include "ErrorReport.hpp"
#include "PoisonCheck.hpp"
#include "MemIntrinsics.hpp"
#include "WhitelistCheck.hpp"
#include "SGXSanLog.hpp"
#include "CiphertextDetect.hpp"

// In order to check safe memory operations:
// If we do not instrument sgxsdk, we should replace memcpy used in memcpy_s with __asan_memcpy(weak symbol) by hand.
// (Current) Or replace memcpy_s with sgxsan_memcpy_s
// If we need to instrument sgxsdk, we needn't extra check, as memcpy will be replaced with __asan_memcpy by llvm pass

void *__asan_memcpy(void *to, const void *from, uptr size)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        if (to != from)
        {
            sgxsan_error(RangesOverlap((const char *)to, size, (const char *)from, size),
                         "[%s] %p:%lu overlap with %p:%lu\n", "memcpy", to, size, from, size);
        }
        bool isSrcInEnclave = false, isDstOutEnclave = false;
        SGXSAN_ELRANGE_CHECK_BEG(from, size)
        ASAN_READ_RANGE(from, size);
        isSrcInEnclave = true;
        SGXSAN_ELRANGE_CHECK_MID
        WhitelistOfAddrOutEnclave_query_ex(from, size, false, false, nullptr);
        SGXSAN_ELRANGE_CHECK_END;
        SGXSAN_ELRANGE_CHECK_BEG(to, size)
        ASAN_WRITE_RANGE(to, size);
        SGXSAN_ELRANGE_CHECK_MID
        isDstOutEnclave = true;
        WhitelistOfAddrOutEnclave_query(to, size);
        SGXSAN_ELRANGE_CHECK_END;
        if (isSrcInEnclave && isDstOutEnclave)
        {
            SGXSAN_WARNING_DETAIL(sgxsan_region_is_poisoned((uint64_t)from, size, ~0x70 | kSGXSanSensitiveObjData), "Plaintext Transfer", (uint64_t)from, size);
            check_output_hybrid((uint64_t)from, size);
        }
    }
    return memcpy(to, from, size);
}

void *__asan_memset(void *block, int c, uptr size)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        SGXSAN_ELRANGE_CHECK_BEG(block, size)
        ASAN_WRITE_RANGE(block, size);
        SGXSAN_ELRANGE_CHECK_MID
        WhitelistOfAddrOutEnclave_query(block, size);
        SGXSAN_ELRANGE_CHECK_END;
    }
    return memset(block, c, size);
}

void *__asan_memmove(void *to, const void *from, uptr size)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        bool isSrcInEnclave = false, isDstOutEnclave = false;
        SGXSAN_ELRANGE_CHECK_BEG(from, size)
        ASAN_READ_RANGE(from, size);
        isSrcInEnclave = true;
        SGXSAN_ELRANGE_CHECK_MID
        WhitelistOfAddrOutEnclave_query_ex(from, size, false, false, nullptr);
        SGXSAN_ELRANGE_CHECK_END;
        SGXSAN_ELRANGE_CHECK_BEG(to, size)
        ASAN_WRITE_RANGE(to, size);
        SGXSAN_ELRANGE_CHECK_MID
        isDstOutEnclave = true;
        WhitelistOfAddrOutEnclave_query(to, size);
        SGXSAN_ELRANGE_CHECK_END;
        if (isSrcInEnclave && isDstOutEnclave)
        {
            SGXSAN_WARNING_DETAIL(sgxsan_region_is_poisoned((uint64_t)from, size, ~0x70 | kSGXSanSensitiveObjData), "Plaintext Transfer", (uint64_t)from, size);
            check_output_hybrid((uint64_t)from, size);
        }
    }
    return memmove(to, from, size);
}

errno_t sgxsan_memcpy_s(void *dst, size_t sizeInBytes, const void *src, size_t count)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        if (dst != src)
        {
            sgxsan_error(RangesOverlap((const char *)dst, sizeInBytes, (const char *)src, count),
                         "[%s] %p:%lu overlap with %p:%lu\n", "memcpy_s", dst, sizeInBytes, src, count);
        }
        bool isSrcInEnclave = false, isDstOutEnclave = false;
        SGXSAN_ELRANGE_CHECK_BEG(src, count)
        ASAN_READ_RANGE(src, count);
        isSrcInEnclave = true;
        SGXSAN_ELRANGE_CHECK_MID
        WhitelistOfAddrOutEnclave_query_ex(src, count, false, false, nullptr);
        SGXSAN_ELRANGE_CHECK_END;
        SGXSAN_ELRANGE_CHECK_BEG(dst, sizeInBytes)
        ASAN_WRITE_RANGE(dst, sizeInBytes);
        SGXSAN_ELRANGE_CHECK_MID
        isDstOutEnclave = true;
        WhitelistOfAddrOutEnclave_query(dst, sizeInBytes);
        SGXSAN_ELRANGE_CHECK_END;
        if (isSrcInEnclave && isDstOutEnclave)
        {
            SGXSAN_WARNING_DETAIL(sgxsan_region_is_poisoned((uint64_t)src, count, ~0x70 | kSGXSanSensitiveObjData), "Plaintext Transfer", (uint64_t)src, count);
            check_output_hybrid((uint64_t)src, count);
        }
    }
    return memcpy_s(dst, sizeInBytes, src, count);
}

errno_t sgxsan_memset_s(void *s, size_t smax, int c, size_t n)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        SGXSAN_ELRANGE_CHECK_BEG(s, smax > n ? smax : n)
        ASAN_WRITE_RANGE(s, smax > n ? smax : n);
        SGXSAN_ELRANGE_CHECK_MID
        WhitelistOfAddrOutEnclave_query(s, smax > n ? smax : n);
        SGXSAN_ELRANGE_CHECK_END;
    }
    return memset_s(s, smax, c, n);
}

int sgxsan_memmove_s(void *dst, size_t sizeInBytes, const void *src, size_t count)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        bool isSrcInEnclave = false, isDstOutEnclave = false;
        SGXSAN_ELRANGE_CHECK_BEG(src, count)
        ASAN_READ_RANGE(src, count);
        isSrcInEnclave = true;
        SGXSAN_ELRANGE_CHECK_MID
        WhitelistOfAddrOutEnclave_query_ex(src, count, false, false, nullptr);
        SGXSAN_ELRANGE_CHECK_END;
        SGXSAN_ELRANGE_CHECK_BEG(dst, sizeInBytes)
        ASAN_WRITE_RANGE(dst, sizeInBytes);
        SGXSAN_ELRANGE_CHECK_MID
        isDstOutEnclave = true;
        WhitelistOfAddrOutEnclave_query(dst, sizeInBytes);
        SGXSAN_ELRANGE_CHECK_END;
        if (isSrcInEnclave && isDstOutEnclave)
        {
            SGXSAN_WARNING_DETAIL(sgxsan_region_is_poisoned((uint64_t)src, count, ~0x70 | kSGXSanSensitiveObjData), "Plaintext Transfer", (uint64_t)src, count);
            check_output_hybrid((uint64_t)src, count);
        }
    }
    return memmove_s(dst, sizeInBytes, src, count);
}