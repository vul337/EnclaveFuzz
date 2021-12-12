#pragma once

#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif
    void sgxsan_edge_check(uint64_t ptr, uint64_t len, int cnt);
#if defined(__cplusplus)
}
#endif
