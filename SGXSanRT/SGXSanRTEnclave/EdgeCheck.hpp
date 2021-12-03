#pragma once

#include <stdint.h>
#if defined(__cplusplus)
extern "C"
{
#endif
    void sgxsan_user_check(uint64_t ptr, uint64_t len, int cnt);
    // a list of c wrapper of WhitelistOfAddrOutEnclave, class member function is inlined defaultly
    void WhitelistOfAddrOutEnclave_init();
    void WhitelistOfAddrOutEnclave_destroy();
    void WhitelistOfAddrOutEnclave_add(uint64_t start, uint64_t size);
    void WhitelistOfAddrOutEnclave_query(uint64_t start, uint64_t size);
#if defined(__cplusplus)
}
#endif