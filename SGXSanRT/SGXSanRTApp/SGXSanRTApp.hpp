#ifndef SGXSAN_RT_APP_HPP
#define SGXSAN_RT_APP_HPP

typedef unsigned long uptr;

#if defined(__cplusplus)
extern "C"
{
#endif

    //defined in Enclave.cpp
    void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr);

#if defined(__cplusplus)
}
#endif

#endif