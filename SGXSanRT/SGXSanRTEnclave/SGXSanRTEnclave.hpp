#ifndef SGXSAN_RT_ENCLAVE_HPP
#define SGXSAN_RT_ENCLAVE_HPP

extern int asan_inited;

void AsanInitFromRtl();

#ifndef ENSURE_ASAN_INITED
#define ENSURE_ASAN_INITED()        \
    do                              \
    {                               \
        if (UNLIKELY(!asan_inited)) \
        {                           \
            AsanInitFromRtl();      \
        }                           \
    } while (0)
#endif

#endif //SGXSAN_RT_ENCLAVE_HPP