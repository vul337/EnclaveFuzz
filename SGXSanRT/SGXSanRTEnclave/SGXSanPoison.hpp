#ifndef SGXSAN_POISON_HPP
#define SGXSAN_POISON_HPP

#include "SGXSanInt.h"

#ifdef __cplusplus
extern "C"
{
#endif
    void __asan_set_shadow_00(uptr addr, uptr size);

    void __asan_set_shadow_f1(uptr addr, uptr size);

    void __asan_set_shadow_f2(uptr addr, uptr size);

    void __asan_set_shadow_f3(uptr addr, uptr size);

    void __asan_set_shadow_f5(uptr addr, uptr size);

    void __asan_set_shadow_f8(uptr addr, uptr size);

    void __asan_set_shadow_fe(uptr addr, uptr size);
#ifdef __cplusplus
}
#endif

#endif // SGXSAN_POISON_HPP