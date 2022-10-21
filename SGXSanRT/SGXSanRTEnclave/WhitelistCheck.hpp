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
void WhitelistQuery(const void *start, size_t size, bool is_write,
                    bool used_to_cmp = false, char *parent_func = nullptr);
void WhitelistGlobalPropagate(const void *addr);
void WhitelistAddInEnclaveAccessCnt();
void WhitelistActive();
void WhitelistDeactive();
#if defined(__cplusplus)
}
#endif
