#include "PoisonSensitiveGlobal.hpp"
#include "SGXSanCommonPoison.hpp"

static uint8_t SENSITIVE_FLAG = 0x20;
void _PoisonSensitiveGlobal(__slsan_global *globalToBePolluted) {

  assert(
      IsAligned(globalToBePolluted->global_variable_addr, SHADOW_GRANULARITY));
  size_t shadowSpanMinusOne =
      (globalToBePolluted->size + (SHADOW_GRANULARITY - 1)) /
          SHADOW_GRANULARITY -
      1;
  uint64_t shadowAddr = MEM_TO_SHADOW(globalToBePolluted->global_variable_addr);
  if (shadowSpanMinusOne > 0)
    memset((void *)shadowAddr, SENSITIVE_FLAG, shadowSpanMinusOne);

  uint64_t lastShadowByteAddr = shadowAddr + shadowSpanMinusOne;
  uint8_t lastShadowByte = *(uint8_t *)lastShadowByteAddr;
  if (lastShadowByte < 8) {
    *(uint8_t *)lastShadowByteAddr = (uint8_t)(lastShadowByte + SENSITIVE_FLAG);
  } else {
    *(uint8_t *)lastShadowByteAddr = SENSITIVE_FLAG;
  }

  // PoisonShadow(globalToBePolluted->global_variable_addr,
  //              globalToBePolluted->size,
  //              globalToBePolluted->poison_value);
}

void PoisonSensitiveGlobal(__slsan_global *globalsToBePolluted, size_t count) {
  for (uptr i = 0; i < count; i++) {
    _PoisonSensitiveGlobal(&globalsToBePolluted[i]);
  }
}