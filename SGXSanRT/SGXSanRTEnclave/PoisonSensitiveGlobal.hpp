#pragma once
#include "SGXSanInt.h"
#include <cstddef>
#include <cstdint>

struct __slsan_global {
  uptr global_variable_addr;
  size_t size;
  uint8_t poison_value;
};

#if defined(__cplusplus)
extern "C" {
#endif
void _PoisonSensitiveGlobal(__slsan_global *globalToBePolluted);
void PoisonSensitiveGlobal(__slsan_global *globalsToBePolluted, size_t count);
#if defined(__cplusplus)
}
#endif