#pragma once

#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif
    void sgxsan_edge_check(void *ptr, uint64_t len, int cnt);
#if defined(__cplusplus)
}
#endif
