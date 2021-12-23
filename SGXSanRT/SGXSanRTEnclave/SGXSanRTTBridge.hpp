#pragma once

#include <sgx_error.h>
#include <sgx_defs.h>
#include <stdint.h>
#include <stddef.h>

typedef unsigned long uptr;
#if defined(__cplusplus)
extern "C"
{
#endif
    sgx_status_t SGX_CDECL ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr);
    sgx_status_t SGX_CDECL sgxsan_ocall_print_string(const char *str);
    sgx_status_t SGX_CDECL sgxsan_ocall_addr2line(uint64_t addr, int level);
    sgx_status_t SGX_CDECL sgxsan_ocall_depcit_distribute(uint64_t addr, unsigned char *byte_arr, size_t byte_arr_size, int bucket_num, bool is_cipher);
#if defined(__cplusplus)
}
#endif