#pragma once
#include "MemAccessMgr.h"
#include "PoisonCheck.h"
#include "SGXSanRTApp.h"

#define REAL(x) real_##x
#define DEFINE_REAL(sym) decltype(sym) *REAL(sym)
#define DECLARE_REAL(sym) extern decltype(sym) *REAL(sym)
#define GET_REAL(sym)                                                          \
  sgxsan_assert(REAL(sym) = (decltype(sym) *)dlsym(RTLD_NEXT, #sym))

DECLARE_REAL(snprintf);
DECLARE_REAL(vsnprintf);

#if defined(__cplusplus)
extern "C" {
#endif
void InitInterceptor();
#if defined(__cplusplus)
}
#endif