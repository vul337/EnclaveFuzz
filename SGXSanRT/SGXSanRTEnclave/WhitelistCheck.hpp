#pragma once

#include <stdint.h>
#include <pthread.h>
#include <map>
#include "SGXSanDefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif
    // a list of c wrapper of WhitelistOfAddrOutEnclave, class member function is inlined defaultly
    void WhitelistOfAddrOutEnclave_init();
    void WhitelistOfAddrOutEnclave_destroy();
    void WhitelistOfAddrOutEnclave_add(uint64_t start, uint64_t size);
    void WhitelistOfAddrOutEnclave_query(uint64_t start, uint64_t size, bool is_write = false);
    void WhitelistOfAddrOutEnclave_global_propagate(uint64_t addr);

    void WhitelistOfAddrOutEnclave_active();
    void WhitelistOfAddrOutEnclave_deactive();
#if defined(__cplusplus)
}
#endif
