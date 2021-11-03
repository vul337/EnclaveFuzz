#include "MemIntrinsics.hpp"

// In order to check safe memory operations:
// (Current) If we do not instrument sgxsdk, we should replace memcpy used in memcpy_s with __asan_memcpy(weak symbol) by hand.
// If we need to instrument sgxsdk, we needn't extra check, as memcpy will be replaced with __asan_memcpy by llvm pass
#if defined(__cplusplus)
extern "C"
{
#endif
    void *memcpy(void *dst0, const void *src0, size_t length);
    void *memmove(void *dst0, const void *src0, size_t length);
    void *memset(void *dst, int c, size_t n);
#if defined(__cplusplus)
}
#endif

#define ASAN_MEMCPY_IMPL(to, from, size)                                                         \
    do                                                                                           \
    {                                                                                            \
        if (LIKELY(asan_inited))                                                                 \
        {                                                                                        \
            ENSURE_ASAN_INITED();                                                                \
            if (to != from)                                                                      \
            {                                                                                    \
                if (RangesOverlap((const char *)to, size, (const char *)from, size))             \
                {                                                                                \
                    printf("[%s] %p:%lu overlap with %p:%lu\n", "memcpy", to, size, from, size); \
                    abort();                                                                     \
                }                                                                                \
            }                                                                                    \
            SGXSAN_ELRANGE_CHECK_BEG(from, 0, size)                                              \
            ASAN_READ_RANGE(from, size);                                                         \
            SGXSAN_ELRANGE_CHECK_END;                                                            \
            SGXSAN_ELRANGE_CHECK_BEG(to, 1, size)                                                \
            ASAN_WRITE_RANGE(to, size);                                                          \
            SGXSAN_ELRANGE_CHECK_END;                                                            \
        }                                                                                        \
        return memcpy(to, from, size);                                                           \
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
