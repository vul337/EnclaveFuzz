#pragma once

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
    void sgxsan_shallow_poison_valid_shadow(uptr addr, uptr size, uint8_t value);
    void sgxsan_shallow_poison_object(uptr addr, uptr size, uint8_t value, bool ignore_shadow_after_scope = false);
    void sgxsan_shallow_poison_aligned_object(uptr addr, uptr size, uint8_t value, bool ignore_shadow_after_scope = false);
    void sgxsan_check_shadow_bytes_match_obj(uptr obj_addr, uptr obj_size, uptr shadow_bytes_len);
    void sgxsan_shallow_shadow_copy_on_mem_transfer(uptr dst_addr, uptr src_addr, uptr dst_size, uptr copy_cnt);
#ifdef __cplusplus
}
#endif
