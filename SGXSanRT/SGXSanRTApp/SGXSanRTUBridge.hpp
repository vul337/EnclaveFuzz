#pragma once
#include "SGXSanRTCom.h"
#include <sgx_eid.h>
#include <sgx_error.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
void sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size,
                                     uint8_t **cov_map_beg_ptr);
void sgxsan_ocall_print_string(const char *str);
void sgxsan_ocall_addr2line(uint64_t *addr_arr, size_t arr_cnt, int level = 0);
void sgxsan_ocall_addr2func_name(uint64_t addr, char *func_name,
                                 size_t buf_size);
void sgxsan_ocall_depcit_distribute(uint64_t addr, unsigned char *byte_arr,
                                    size_t byte_arr_size, int bucket_num,
                                    bool is_cipher);
#if defined(__cplusplus)
}
#endif