#include "Poison.hpp"
#include "PoisonCheck.hpp"
#include <sgx_trts.h>
#include <string.h>

static const u64 kAllocaRedzoneSize = 32UL;
static const u64 kAllocaRedzoneMask = 31UL;

extern "C" {
/* Callbacks of ASan pass */
// Used by static allocas
void __asan_set_shadow_00(uptr addr, uptr size) {
  memset((void *)addr, 0, size);
}

void __asan_set_shadow_f1(uptr addr, uptr size) {
  memset((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(uptr addr, uptr size) {
  memset((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(uptr addr, uptr size) {
  memset((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(uptr addr, uptr size) {
  memset((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(uptr addr, uptr size) {
  memset((void *)addr, 0xf8, size);
}

void __asan_set_shadow_fe(uptr addr, uptr size) {
  memset((void *)addr, 0xfe, size);
}

// Used by dynamic allocas
// lifetime.start/end
void __asan_poison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanStackUseAfterScopeMagic);
}

void __asan_unpoison_stack_memory(uptr addr, uptr size) {
  UnPoisonShadow(addr, size);
}

// Init time
void __asan_alloca_poison(uptr addr, uptr size) {
  sgxsan_assert(addr && AddrIsAlignedByGranularity(addr));
  uptr LeftRedzoneAddr = addr - kAllocaRedzoneSize;
  uptr PartialRzAddr = addr + size;
  uptr RightRzAddr = (PartialRzAddr + kAllocaRedzoneMask) & ~kAllocaRedzoneMask;
  uptr PartialRzAligned = PartialRzAddr & ~(SHADOW_GRANULARITY - 1);
  FastPoisonShadow(LeftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
  FastPoisonShadowPartialRightRedzone(
      PartialRzAligned, PartialRzAddr % SHADOW_GRANULARITY,
      RightRzAddr - PartialRzAligned, kAsanAllocaRightMagic);
  FastPoisonShadow(RightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

void __asan_allocas_unpoison(uptr top, uptr bottom) {
  if ((!top) || (top > bottom))
    return;
  memset(reinterpret_cast<void *>(MemToShadow(top)), 0,
         (bottom - top) / SHADOW_GRANULARITY);
}

/* Level 2 Poison - Reflect extra information */
/* Callbacks of SGXSan */
void ShallowPoisonShadow(uptr addr, uptr size, uint8_t value) {
  sgxsan_assert(size > 0 and (value == kSGXSanSensitiveLayout or
                              value == kSGXSanSensitiveObjData));
  uptr aligned_addr = RoundDownTo(addr, SHADOW_GRANULARITY);
  size += (addr - aligned_addr);

  uint8_t *shadow_beg = (uint8_t *)MEM_TO_SHADOW(aligned_addr);
  uptr shadow_size = RoundUpDiv(size, SHADOW_GRANULARITY);
  for (size_t i = 0; i < shadow_size; i++) {
    uint8_t shadow_value = shadow_beg[i];
    if (shadow_value < 0x80) {
      shadow_beg[i] = value | shadow_value;
    }
  }
}

void ShallowUnPoisonShadow(uptr addr, uptr size) {
  sgxsan_assert(size > 0);

  uptr aligned_addr = RoundDownTo(addr, SHADOW_GRANULARITY);
  size += (addr - aligned_addr);

  uint8_t *shadow_beg = (uint8_t *)MEM_TO_SHADOW(aligned_addr);
  uptr shadow_size = RoundUpDiv(size, SHADOW_GRANULARITY);
  for (size_t i = 0; i < shadow_size; i++) {
    uint8_t shadow_value = shadow_beg[i];
    if (shadow_value < 0x80) {
      shadow_beg[i] = (uint8_t)(shadow_value & 0x0F);
    }
  }
}

void sgxsan_check_shadow_bytes_match_obj(uptr obj_addr, uptr obj_size,
                                         uptr shadow_bytes_len) {
  sgxsan_assert(obj_size > 0 && obj_addr % SHADOW_GRANULARITY == 0);
  sgxsan_assert((obj_size + SHADOW_GRANULARITY - 1) / SHADOW_GRANULARITY >=
                shadow_bytes_len);
}

// we assume operated memory is valid, otherwise mem transfer operation before
// this call will abort
void sgxsan_shallow_shadow_copy_on_mem_transfer(uptr dst_addr, uptr src_addr,
                                                uptr dst_size, uptr copy_cnt) {
  // should already instrumented check at Pass-End
  sgxsan_assert(dst_size != 0 && copy_cnt != 0 &&
                sgxsan_region_is_in_elrange_and_poisoned(
                    src_addr, copy_cnt, kSGXSanSensitiveObjData) &&
                sgx_is_within_enclave((void *)dst_addr, dst_size));

  if (copy_cnt > dst_size)
    copy_cnt = dst_size;

  uint8_t *dst_shadow_addr = (uint8_t *)(MEM_TO_SHADOW(dst_addr));
  uint8_t *src_shadow_addr = (uint8_t *)(MEM_TO_SHADOW(src_addr));
  uptr dst_shadow_size =
      (dst_size + SHADOW_GRANULARITY - 1) / SHADOW_GRANULARITY;
  uptr src_shadow_size =
      (copy_cnt + SHADOW_GRANULARITY - 1) / SHADOW_GRANULARITY;
  sgxsan_assert(src_shadow_size <= dst_shadow_size);

  memcpy(dst_shadow_addr, src_shadow_addr, src_shadow_size - 1);

  // there is a situation that small-size src memory copied to large-size dst
  // memory so directly copy shadow of src to dst may cause problem
  dst_shadow_addr[src_shadow_size - 1] =
      (uint8_t)((src_shadow_addr[src_shadow_size - 1] & 0xF0) +
                (dst_shadow_addr[src_shadow_size - 1] & 0xF));
}
}
