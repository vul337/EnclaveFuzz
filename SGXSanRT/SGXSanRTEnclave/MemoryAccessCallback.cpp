#include "ErrorReport.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanDefs.h"
#include "WhitelistCheck.hpp"

#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                      \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_##type##size(            \
      uptr addr, bool used_to_cmp, char *parent_func) {                        \
    SGXSAN_ELRANGE_CHECK_BEG(addr, size)                                       \
    uptr smp = MEM_TO_SHADOW(addr);                                            \
    uptr s = size <= SHADOW_GRANULARITY                                        \
                 ? ((*reinterpret_cast<u8 *>(smp)) & (0x8F))                   \
                 : ((*reinterpret_cast<u16 *>(smp)) & (0x8F8F));               \
    if (UNLIKELY(s)) {                                                         \
      if (UNLIKELY(size >= SHADOW_GRANULARITY ||                               \
                   ((s8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=     \
                       (s8)s)) {                                               \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);            \
      }                                                                        \
    }                                                                          \
    SGXSAN_ELRANGE_CHECK_MID                                                   \
    WhitelistQuery((void *)addr, size, is_write, used_to_cmp, parent_func);    \
    SGXSAN_ELRANGE_CHECK_END;                                                  \
  }

ASAN_MEMORY_ACCESS_CALLBACK(load, false, 1)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 2)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 4)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 8)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 16)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 1)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 2)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 4)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 8)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 16)

extern "C" NOINLINE INTERFACE_ATTRIBUTE void
__asan_loadN(uptr addr, uptr size, bool used_to_cmp, char *parent_func) {
  SGXSAN_ELRANGE_CHECK_BEG(addr, size)
  if (sgxsan_region_is_poisoned(addr, size)) {
    GET_CALLER_PC_BP_SP;
    ReportGenericError(pc, bp, sp, addr, false, size, true);
  }
  SGXSAN_ELRANGE_CHECK_MID
  WhitelistQuery((void *)addr, size, false, used_to_cmp, parent_func);
  SGXSAN_ELRANGE_CHECK_END;
}

extern "C" NOINLINE INTERFACE_ATTRIBUTE void
__asan_storeN(uptr addr, uptr size, bool used_to_cmp, char *parent_func) {
  SGXSAN_ELRANGE_CHECK_BEG(addr, size)
  if (sgxsan_region_is_poisoned(addr, size)) {
    GET_CALLER_PC_BP_SP;
    ReportGenericError(pc, bp, sp, addr, true, size, true);
  }
  SGXSAN_ELRANGE_CHECK_MID
  WhitelistQuery((void *)addr, size, true, used_to_cmp, parent_func);
  SGXSAN_ELRANGE_CHECK_END;
}