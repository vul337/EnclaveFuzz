#include "EdgeCheck.hpp"
#include "WhitelistCheck.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanCommonErrorReport.hpp"
#include "SGXSanPrintf.hpp"

void sgxsan_edge_check(uint64_t ptr, uint64_t len, int cnt)
{
    uint64_t min_size = len * std::max(1, cnt);
    if (min_size < len)
    {
        // int overflow
        min_size = len;
    }
    SGXSAN_ELRANGE_CHECK_BEG(ptr, 0, min_size)
    if (sgxsan_region_is_poisoned(ptr, min_size, (~0x70) | kSGXSanSensitiveLayout))
    {
        // PrintErrorAndAbort("[sgxsan_edge_check] 0x%lx point to sensitive area\n", ptr);
        GET_CALLER_PC_BP_SP;
        ReportGenericError(pc, bp, sp, ptr, 0, min_size, false);
    }
    SGXSAN_ELRANGE_CHECK_MID
    // totally outside enclave, add to whitelist
    WhitelistOfAddrOutEnclave_add(ptr, (cnt == -1) ? (1 << 9) : (len * cnt));
    SGXSAN_ELRANGE_CHECK_END;
    return;
}
