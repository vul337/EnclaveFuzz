#pragma once

#include "SGXSanDefs.h"
#include <map>
#include <pthread.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
// a list of c wrapper of WhitelistOfAddrOutEnclave, class member function is
// inlined defaultly
void WhitelistOfAddrOutEnclave_init();
void WhitelistOfAddrOutEnclave_destroy();
void WhitelistOfAddrOutEnclave_add(const void *start, size_t size);
void WhitelistOfAddrOutEnclave_query_ex(const void *start, size_t size,
                                        bool is_write, bool used_to_cmp = false,
                                        char *parent_func = nullptr);
void WhitelistOfAddrOutEnclave_query(const void *start, size_t size);
void WhitelistOfAddrOutEnclave_global_propagate(const void *addr);
void WhitelistOfAddrOutEnclave_add_in_enclave_access_cnt();
void WhitelistOfAddrOutEnclave_active();
void WhitelistOfAddrOutEnclave_deactive();
#if defined(__cplusplus)
}
#endif
