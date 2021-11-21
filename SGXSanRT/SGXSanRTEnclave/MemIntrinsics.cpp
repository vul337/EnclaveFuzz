#include <string.h>
#include <errno.h>
#include <assert.h>
#include <mbusafecrt.h>
#include "MemIntrinsics.hpp"

// In order to check safe memory operations:
// If we do not instrument sgxsdk, we should replace memcpy used in memcpy_s with __asan_memcpy(weak symbol) by hand.
// (Current) Or replace memcpy_s with sgxsan_memcpy_s
// If we need to instrument sgxsdk, we needn't extra check, as memcpy will be replaced with __asan_memcpy by llvm pass

#define ASAN_MEMCPY_IMPL(to, from, size)                                                                     \
    do                                                                                                       \
    {                                                                                                        \
        if (LIKELY(asan_inited))                                                                             \
        {                                                                                                    \
            ENSURE_ASAN_INITED();                                                                            \
            if (to != from)                                                                                  \
            {                                                                                                \
                if (RangesOverlap((const char *)to, size, (const char *)from, size))                         \
                {                                                                                            \
                    PrintErrorAndAbort("[%s] %p:%lu overlap with %p:%lu\n", "memcpy", to, size, from, size); \
                }                                                                                            \
            }                                                                                                \
            SGXSAN_ELRANGE_CHECK_BEG(from, 0, size)                                                          \
            ASAN_READ_RANGE(from, size);                                                                     \
            SGXSAN_ELRANGE_CHECK_END;                                                                        \
            SGXSAN_ELRANGE_CHECK_BEG(to, 1, size)                                                            \
            ASAN_WRITE_RANGE(to, size);                                                                      \
            SGXSAN_ELRANGE_CHECK_END;                                                                        \
        }                                                                                                    \
        return memcpy(to, from, size);                                                                       \
    } while (0)

#define ASAN_MEMSET_IMPL(block, c, size)             \
    do                                               \
    {                                                \
        if (LIKELY(asan_inited))                     \
        {                                            \
            ENSURE_ASAN_INITED();                    \
            SGXSAN_ELRANGE_CHECK_BEG(block, 1, size) \
            ASAN_WRITE_RANGE(block, size);           \
            SGXSAN_ELRANGE_CHECK_END;                \
        }                                            \
        return memset(block, c, size);               \
    } while (0)

#define ASAN_MEMMOVE_IMPL(to, from, size)           \
    do                                              \
    {                                               \
        if (LIKELY(asan_inited))                    \
        {                                           \
            ENSURE_ASAN_INITED();                   \
            SGXSAN_ELRANGE_CHECK_BEG(from, 0, size) \
            ASAN_READ_RANGE(from, size);            \
            SGXSAN_ELRANGE_CHECK_END;               \
            SGXSAN_ELRANGE_CHECK_BEG(to, 1, size)   \
            ASAN_WRITE_RANGE(to, size);             \
            SGXSAN_ELRANGE_CHECK_END;               \
        }                                           \
        return memmove(to, from, size);             \
    } while (0)

#define _VALIDATE_RETURN_ERRCODE(expr, errorcode) \
    {                                             \
        int _Expr_val = !!(expr);                 \
        assert((_Expr_val) && (#expr));           \
        if (!(_Expr_val))                         \
        {                                         \
            errno = errorcode;                    \
            assert(0 && (#expr));                 \
            return (errorcode);                   \
        }                                         \
    }

void *__asan_memcpy(void *to, const void *from, uptr size)
{
    ASAN_MEMCPY_IMPL(to, from, size);
}

void *__asan_memset(void *block, int c, uptr size)
{
    ASAN_MEMSET_IMPL(block, c, size);
}

void *__asan_memmove(void *to, const void *from, uptr size)
{
    ASAN_MEMMOVE_IMPL(to, from, size);
}

errno_t sgxsan_memcpy_s(void *dst, size_t sizeInBytes, const void *src, size_t count)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        if (dst != src)
        {
            if (RangesOverlap((const char *)dst, sizeInBytes, (const char *)src, count))
            {
                PrintErrorAndAbort("[%s] %p:%lu overlap with %p:%lu\n", "memcpy_s", dst, sizeInBytes, src, count);
            }
        }
        SGXSAN_ELRANGE_CHECK_BEG(src, 0, count)
        ASAN_READ_RANGE(src, count);
        SGXSAN_ELRANGE_CHECK_END;
        SGXSAN_ELRANGE_CHECK_BEG(dst, 1, sizeInBytes)
        ASAN_WRITE_RANGE(dst, sizeInBytes);
        SGXSAN_ELRANGE_CHECK_END;
    }
    return memcpy_s(dst, sizeInBytes, src, count);
}

errno_t sgxsan_memset_s(void *s, size_t smax, int c, size_t n)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        SGXSAN_ELRANGE_CHECK_BEG(s, 1, smax > n ? smax : n)
        ASAN_WRITE_RANGE(s, smax > n ? smax : n);
        SGXSAN_ELRANGE_CHECK_END;
    }
    return memset_s(s, smax, c, n);
}

int sgxsan_memmove_s(void *dst, size_t sizeInBytes, const void *src, size_t count)
{
    if (LIKELY(asan_inited))
    {
        ENSURE_ASAN_INITED();
        SGXSAN_ELRANGE_CHECK_BEG(src, 0, count)
        ASAN_READ_RANGE(src, count);
        SGXSAN_ELRANGE_CHECK_END;
        SGXSAN_ELRANGE_CHECK_BEG(dst, 1, sizeInBytes)
        ASAN_WRITE_RANGE(dst, sizeInBytes);
        SGXSAN_ELRANGE_CHECK_END;
    }
    return memmove_s(dst, sizeInBytes, src, count);
}