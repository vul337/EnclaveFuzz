#ifndef SGXSAN_RT_APP_HPP
#define SGXSAN_RT_APP_HPP

typedef unsigned long uptr;

#if defined(__cplusplus)
extern "C"
{
#endif
    void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr);
    void sgxsan_ocall_print_string(const char *str);
    void sgxsan_ocall_addr2line(uint64_t addr, int level = 0);
#if defined(__cplusplus)
}
#endif

#endif