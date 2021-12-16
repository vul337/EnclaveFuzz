#include "EdgeCheck.hpp"
#include "WhitelistCheck.hpp"
#include "SGXSanCommonPoisonCheck.hpp"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanPrintf.hpp"

void sgxsan_edge_check(uint64_t ptr, uint64_t len, int cnt)
{
    SGXSAN_ELRANGE_CHECK_BEG(ptr, 0, len * (cnt <= 1 ? 1 : cnt))
    if (__asan_region_is_poisoned(ptr, len * (cnt <= 1 ? 1 : cnt), true))
    {
        PrintErrorAndAbort("[sgxsan_edge_check] 0x%lx point to sensitive area\n", ptr);
    }
    SGXSAN_ELRANGE_CHECK_MID
    //totally outside enclave, add to whitelist
    ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(ptr, (cnt == -1) ? (1 << 12) : (len * cnt)).second, "Insertion conflict?");
    SGXSAN_ELRANGE_CHECK_END;
    return;
}
