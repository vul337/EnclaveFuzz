#include "EdgeCheck.hpp"
#include "WhitelistCheck.hpp"
#include "PoisonCheck.hpp"
#include "ErrorReport.hpp"

void sgxsan_edge_check(void *ptr, uint64_t len, int cnt)
{
    assert(len > 0 && cnt != 0);
    uint64_t min_size = len * std::max(1, cnt);
    if (min_size < len)
    {
        // int overflow
        min_size = len;
    }
    SGXSAN_ELRANGE_CHECK_BEG((uptr)ptr, min_size)
    if (sgxsan_region_is_poisoned((uptr)ptr, min_size, 0x8F | kSGXSanSensitiveLayout))
    {
        GET_CALLER_PC_BP_SP;
        ReportGenericError(pc, bp, sp, (uptr)ptr, 0, min_size, false);
    }
    SGXSAN_ELRANGE_CHECK_MID
    // totally outside enclave, add to whitelist
    WhitelistOfAddrOutEnclave_add(ptr, (cnt == -1) ? (1 << 10) : (len * cnt));
    SGXSAN_ELRANGE_CHECK_END;
    return;
}
