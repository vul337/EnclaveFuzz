#ifndef MEM_INTRINSICS_HPP
#define MEM_INTRINSICS_HPP

#include <errno.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif
    void *__asan_memcpy(void *to, const void *from, uptr size);
    void *__asan_memset(void *block, int c, uptr size);
    void *__asan_memmove(void *to, const void *from, uptr size);
    errno_t sgxsan_memcpy_s(void *dst, size_t sizeInBytes, const void *src, size_t count);
    errno_t sgxsan_memset_s(void *s, size_t smax, int c, size_t n);
    int sgxsan_memmove_s(void *dst, size_t sizeInBytes, const void *src, size_t count);
#if defined(__cplusplus)
}
#endif

#endif