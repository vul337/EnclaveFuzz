#ifndef MALLOC_HPP
#define MALLOC_HPP

#include "SGXSanCheck.h"
#include "SGXSanDefs.h"

// rz_log represent 2^(rz_log+4)
static inline uptr ComputeRZLog(uptr user_requested_size)
{
    u32 rz_log = user_requested_size <= 64 - 16            ? 0
                 : user_requested_size <= 128 - 32         ? 1
                 : user_requested_size <= 512 - 64         ? 2
                 : user_requested_size <= 4096 - 128       ? 3
                 : user_requested_size <= (1 << 14) - 256  ? 4
                 : user_requested_size <= (1 << 15) - 512  ? 5
                 : user_requested_size <= (1 << 16) - 1024 ? 6
                                                           : 7;

    return rz_log;
}

static inline u32 RZLog2Size(u32 rz_log)
{
    CHECK_LT(rz_log, 8);
    return 16 << rz_log;
}

static inline uptr ComputeRZSize(uptr size)
{
    return 16 << ComputeRZLog(size);
}

#if defined(__cplusplus)
extern "C"
{
#endif
    void *sgxsan_malloc(size_t size);
    void sgxsan_free(void *ptr);
    void *sgxsan_calloc(size_t n_elements, size_t elem_size);
    void *sgxsan_realloc(void *oldmem, size_t bytes);
#if defined(__cplusplus)
}
#endif

#endif