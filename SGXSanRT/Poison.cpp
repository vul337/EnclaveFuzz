#include "Poison.h"
#include <algorithm>
#include <string.h>

/// Callback for SGXSan Pass
/// Used by static allocas
/// Already applied InEnclave flag in PASS before call these
#define ASAN_SET_SHADOW(shadowValue)                                           \
  extern "C" void __asan_set_shadow_##shadowValue(uptr addr, uptr size) {      \
    memset((void *)addr, L1F(0x##shadowValue), size);                          \
  }

ASAN_SET_SHADOW(00)
ASAN_SET_SHADOW(f1)
ASAN_SET_SHADOW(f2)
ASAN_SET_SHADOW(f3)
ASAN_SET_SHADOW(f5)
ASAN_SET_SHADOW(f8)
ASAN_SET_SHADOW(fe)

/// Used by dynamic allocas
extern "C" void __asan_poison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanStackUseAfterScopeMagic);
}

extern "C" void __asan_unpoison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanNotPoisonedMagic, true);
}

static const uint64_t kAllocaRedzoneSize = 32UL;

extern "C" void __asan_alloca_poison(uptr addr, uptr size) {
  /// LeftRedzoneAddr < addr < PartialRzAligned <= PartialRzAddr <= RightRzAddr
  uptr LeftRedzoneAddr = addr - kAllocaRedzoneSize;
  uptr PartialRzAddr = addr + size;
  uptr RightRzAddr = RoundUpTo(PartialRzAddr, kAllocaRedzoneSize);
  uptr PartialRzAligned = RoundDownTo(PartialRzAddr, SHADOW_GRANULARITY);

  FastPoisonShadow(LeftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
  FastPoisonShadow(addr, PartialRzAligned - addr, kAsanNotPoisonedMagic);
  FastPoisonShadowPartialRightRedzone(
      PartialRzAligned, PartialRzAddr % SHADOW_GRANULARITY,
      RightRzAddr - PartialRzAligned, kAsanAllocaRightMagic);
  FastPoisonShadow(RightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

extern "C" void __asan_allocas_unpoison(uptr top, uptr bottom) {
  if ((!top) || (top > bottom))
    return;
  FastMemSet((void *)MemToShadow(top), kAsanNotPoisonedMagic,
             (bottom - top) / SHADOW_GRANULARITY);
}

/// Level 1 API
void FastPoisonShadow(uptr aligned_addr, uptr aligned_size, uint8_t value,
                      bool returnBackToNormal) {
  FastMemSet((void *)MEM_TO_SHADOW(aligned_addr),
             returnBackToNormal ? value : L0P(value),
             aligned_size / SHADOW_GRANULARITY);
}

/// Poison valid memory with right redzone
void FastPoisonShadowPartialRightRedzone(uptr aligned_addr, uptr size,
                                         uptr aligned_size_with_rz,
                                         uint8_t rz_value) {
  uint8_t *shadow = (uint8_t *)MEM_TO_SHADOW(aligned_addr);
  for (uptr i = 0; i < aligned_size_with_rz; i += SHADOW_GRANULARITY) {
    shadow[i / SHADOW_GRANULARITY] =
        L0P(i + SHADOW_GRANULARITY <= size ? kAsanNotPoisonedMagic
            : i >= size                    ? rz_value
                                           : size - i);
  }
}

void PoisonShadow(uptr addr, uptr size, uint8_t value,
                   bool returnBackToNormal) {
  // If addr do not aligned at granularity, start posioning from
  // RoundUpTo(addr, granularity)
  if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY))) {
    uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
    size -= aligned_addr - addr;
    addr = aligned_addr;
  }

  uint8_t remained = size & (SHADOW_GRANULARITY - 1);
  FastPoisonShadow(addr, size - remained, value, returnBackToNormal);

  if (remained) {
    uint8_t *shadowEnd = (uint8_t *)MEM_TO_SHADOW(addr + size - remained);
    int8_t origValue = L1F(*shadowEnd);
    if (value >= 0x80) {
      if (0 <= origValue && origValue <= (int8_t)remained)
        *shadowEnd = L0P(value);
    } else if (value == kAsanNotPoisonedMagic) {
      uint8_t poisonVal = std::max(origValue, (int8_t)remained);
      *shadowEnd = returnBackToNormal ? poisonVal : L0P(poisonVal);
    } else {
      abort();
    }
  }
}

// This structure is used to describe the source location of a place where
// global was defined.
struct __asan_global_source_location {
  const char *filename;
  int line_no;
  int column_no;
};

// This structure describes an instrumented global variable.
struct SGXSanGlobal {
  uptr beg;                // The address of the global.
  uptr size;               // The original size of the global.
  uptr size_with_redzone;  // The size with the redzone.
  const char *name;        // Name as a C string.
  const char *module_name; // Module name as a C string. This pointer is a
                           // unique identifier of a module.
  uptr has_dynamic_init;   // Non-zero if the global has dynamic initializer.
  __asan_global_source_location *location; // Source location of a global,
                                           // or NULL if it is unknown.
  uptr odr_indicator; // The address of the ODR indicator symbol.
};

// Register a global variable.
// This function may be called more than once for every global
// so we store the globals in a map.
static void RegisterGlobal(const SGXSanGlobal *g) {
  sgxsan_assert(asan_inited and AddrIsInMem(g->beg));
  sgxsan_error(!IsAligned(g->beg, SHADOW_GRANULARITY),
               "The following global variable is not properly aligned.\n"
               "This may happen if another global with the same name\n"
               "resides in another non-instrumented module.\n"
               "Or the global comes from a C file built w/o -fno-common.\n"
               "In either case this is likely an ODR violation bug,\n"
               "but AddressSanitizer can not provide more details.\n");
  sgxsan_assert(IsAligned(g->size_with_redzone, SHADOW_GRANULARITY));

  uptr aligned_size = RoundUpTo(g->size, SHADOW_GRANULARITY);
  sgxsan_assert(g->size_with_redzone > aligned_size);
  FastPoisonShadow(g->beg, aligned_size, kAsanNotPoisonedMagic);
  FastPoisonShadow(g->beg + aligned_size, g->size_with_redzone - aligned_size,
                   kAsanGlobalRedzoneMagic);
  if (g->size != aligned_size) {
    FastPoisonShadowPartialRightRedzone(
        g->beg + RoundDownTo(g->size, SHADOW_GRANULARITY),
        g->size % SHADOW_GRANULARITY, SHADOW_GRANULARITY,
        kAsanGlobalRedzoneMagic);
  }
}

// Register an array of globals.
extern "C" void __asan_register_globals(SGXSanGlobal *globals, uptr n) {
  RunInEnclave = true;
  for (uptr i = 0; i < n; i++) {
    RegisterGlobal(&globals[i]);
  }

  // Poison the metadata. It should not be accessible to user code.
  PoisonShadow((uptr)globals, n * sizeof(SGXSanGlobal),
               kAsanGlobalRedzoneMagic);
  RunInEnclave = false;
}

static void UnregisterGlobal(const SGXSanGlobal *g) {
  sgxsan_assert(asan_inited and AddrIsInMem(g->beg) and
                IsAligned(g->beg, SHADOW_GRANULARITY) and
                IsAligned(g->size_with_redzone, SHADOW_GRANULARITY));

  FastPoisonShadow(g->beg, g->size_with_redzone, kAsanNotPoisonedMagic, true);
}

// Unregister an array of globals.
// We must do this when a shared objects gets dlclosed.
extern "C" void __asan_unregister_globals(SGXSanGlobal *globals, uptr n) {
  for (uptr i = 0; i < n; i++) {
    UnregisterGlobal(&globals[i]);
  }

  // Unpoison the metadata.
  PoisonShadow((uptr)globals, n * sizeof(SGXSanGlobal), kAsanNotPoisonedMagic,
               true);
}

/// Level 2 Poison
///
/// Used to shallow poison sensitive data
void ShallowPoisonShadow(uptr addr, uptr size, uint8_t value, bool doPoison) {
  if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY))) {
    uptr aligned_addr = RoundDownTo(addr, SHADOW_GRANULARITY);
    size += addr - aligned_addr;
    addr = aligned_addr;
  }
  uptr *p_shadow = (uptr *)MEM_TO_SHADOW(addr);
  uptr shadow_size = RoundUpDiv(size, SHADOW_GRANULARITY);
  uptr extendedValue = ExtendInt8(value);
  size_t step_size = sizeof(uptr), step_times = shadow_size / step_size,
         remained = shadow_size % step_size;
  uint8_t *p_shadow_remained =
      (uint8_t *)((uptr)p_shadow + shadow_size - remained);
  if (doPoison) {
    for (size_t step = 0; step < step_times; step++) {
      p_shadow[step] |= extendedValue;
    }
    for (size_t i = 0; i < remained; i++) {
      p_shadow_remained[i] |= value;
    }
  } else {
    uptr unpoisonValue = ~extendedValue;
    for (size_t step = 0; step < step_times; step++) {
      p_shadow[step] &= unpoisonValue;
    }
    for (size_t i = 0; i < remained; i++) {
      p_shadow_remained[i] &= ~value;
    }
  }
}

void MoveShallowShadow(uptr dst_addr, uptr src_addr, uptr dst_size,
                       uptr copy_cnt) {
  uint8_t *dst_shadow_addr = (uint8_t *)MEM_TO_SHADOW(dst_addr);
  uint8_t *src_shadow_addr = (uint8_t *)MEM_TO_SHADOW(src_addr);
  for (size_t i = 0;
       i < RoundUpDiv(std::min(dst_size, copy_cnt), SHADOW_GRANULARITY); i++) {
    *dst_shadow_addr |= L2F(*src_shadow_addr);
  }
}

struct SLSanGlobal {
  uptr beg;
  size_t size;
};

static void RegisterSensitiveGlobal(SLSanGlobal *g) {
  sgxsan_assert(IsAligned(g->beg, SHADOW_GRANULARITY));
  size_t shadowSize = RoundUpDiv(g->size, SHADOW_GRANULARITY);
  uint8_t *shadowAddr = (uint8_t *)MEM_TO_SHADOW(g->beg);
  for (size_t i = 0; i < shadowSize; i++) {
    *shadowAddr |= kSGXSanSensitiveObjData;
  }
}

extern "C" void PoisonSensitiveGlobal(SLSanGlobal *globals, size_t n) {
  for (uptr i = 0; i < n; i++) {
    RegisterSensitiveGlobal(&globals[i]);
  }
  // Poison the metadata. It should not be accessible to user code.
  PoisonShadow((uptr)globals, n * sizeof(SLSanGlobal), kAsanGlobalRedzoneMagic);
}