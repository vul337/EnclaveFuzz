#include "EdgeCheck.hpp"
#include "SGXSanCommonPoisonCheck.hpp"
#include "SGXSanCommonErrorReport.hpp"
// #include "Printf.h"

void sgxsan_user_check(uint64_t ptr, uint64_t len)
{
    SGXSAN_ELRANGE_CHECK_BEG(ptr, 0, len)
    if (__asan_region_is_poisoned(ptr, len, true))
    {
        PrintErrorAndAbort("[sgxsan_user_check] 0x%lx point to sensitive area\n", ptr);
    }
    SGXSAN_ELRANGE_CHECK_END;
    return;
}