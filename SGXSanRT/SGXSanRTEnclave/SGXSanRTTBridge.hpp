#pragma once

#include <sgx_error.h>
#include <sgx_defs.h>
#include <stdint.h>
#include <stddef.h>
#include "SGXSanInt.h"

#if defined(__cplusplus)
extern "C"
{
#endif
    sgx_status_t SGX_CDECL sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr);
    sgx_status_t SGX_CDECL sgxsan_ocall_print_string(const char *str);
    sgx_status_t SGX_CDECL sgxsan_ocall_addr2line(uint64_t addr, int level = 0);
    sgx_status_t SGX_CDECL sgxsan_ocall_addr2line_ex(uint64_t *addr_arr, size_t arr_cnt, int level = 0);
    sgx_status_t SGX_CDECL sgxsan_ocall_addr2func_name(uint64_t addr, char *func_name, size_t buf_size);
    sgx_status_t SGX_CDECL sgxsan_ocall_depcit_distribute(uint64_t addr, unsigned char *byte_arr, size_t byte_arr_size, int bucket_num, bool is_cipher);
    sgx_status_t SGX_CDECL sgxsan_ocall_get_mmap_infos(void *mmap_infos, size_t max_size, size_t *real_size);
#if defined(__cplusplus)
}
#endif