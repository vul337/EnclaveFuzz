#include "PoisonSensitiveGlobal.hpp"
#include "Poison.hpp"
#include <string.h>

void _PoisonSensitiveGlobal(__slsan_global *globalToBePolluted) {

  sgxsan_assert(
      IsAligned(globalToBePolluted->global_variable_addr, SHADOW_GRANULARITY));
  ShallowPoisonShadow(globalToBePolluted->global_variable_addr,
                      globalToBePolluted->size, kSGXSanSensitiveObjData);
}

void PoisonSensitiveGlobal(__slsan_global *globalsToBePolluted, size_t count) {
  for (uptr i = 0; i < count; i++) {
    _PoisonSensitiveGlobal(&globalsToBePolluted[i]);
  }
  // Poison the metadata. It should not be accessible to user code.
  PoisonShadow((uptr)globalsToBePolluted, count * sizeof(__slsan_global),
               kAsanGlobalRedzoneMagic);
}