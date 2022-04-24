#ifndef POISON_HPP
#define POISON_HPP

#include "SGXSanInt.h"
#include <cstdint>

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
    void __asan_poison_stack_memory(uptr addr, uptr size);
    void __asan_unpoison_stack_memory(uptr addr, uptr size);
    void __asan_alloca_poison(uptr addr, uptr size);
    void __asan_allocas_unpoison(uptr addr, uptr size);
    void __sgxsan_shallow_poison_valid_shadow(uptr addr, uptr size, uint8_t value);
#ifdef __cplusplus
}
#endif

#endif