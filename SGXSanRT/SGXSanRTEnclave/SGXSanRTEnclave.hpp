#pragma once

#include <cstddef>

extern int asan_inited;

#if defined(__cplusplus)
extern "C"
{
#endif
    void AsanInitFromRtl();
    void __asan_init();
    void get_mmap_infos();
    bool is_pointer_readable(void *ptr, size_t element_size, int count);
#if defined(__cplusplus)
}
#endif

#ifndef ENSURE_ASAN_INITED
#define ENSURE_ASAN_INITED()        \
    do                              \
    {                               \
        if (UNLIKELY(!asan_inited)) \
        {                           \
            AsanInitFromRtl();      \
        }                           \
    } while (0)
#endif
