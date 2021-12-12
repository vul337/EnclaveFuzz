#include "EdgeCheck.hpp"
#include "WhitelistCheck.hpp"
#include "SGXSanCommonPoisonCheck.hpp"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanPrintf.hpp"

void sgxsan_edge_check(uint64_t ptr, uint64_t len, int cnt)
{
    SGXSAN_ELRANGE_CHECK_BEG(ptr, 0, len)
    if (__asan_region_is_poisoned(ptr, len, true))
    {
        PrintErrorAndAbort("[sgxsan_edge_check] 0x%lx point to sensitive area\n", ptr);
    }
    SGXSAN_ELRANGE_CHECK_MID
    //totally outside enclave, add to whitelist
    if (cnt == -1)
    {
        ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(ptr, 1 << 12).second, "Insertion conflict?");
    }
    else
    {
        ABORT_ASSERT(WhitelistOfAddrOutEnclave::add(ptr, len * cnt).second, "Insertion conflict?");
    }
    SGXSAN_ELRANGE_CHECK_END;

    return;
}
