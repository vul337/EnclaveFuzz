#include "Interceptor.h"
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

DEFINE_REAL(vsnprintf) = nullptr;
DEFINE_REAL(snprintf) = nullptr;

void InitInterceptor() {
  static bool HasInit = false;
  if (HasInit)
    return;
  GET_REAL(vsnprintf);
  GET_REAL(snprintf);
  HasInit = true;
}

extern "C" int snprintf(char *__restrict __s, size_t __maxlen,
                        const char *__restrict __format, ...) {
  InitInterceptor();
  InOutEnclaveStatus RegionInOutEnclaveStatus;
  uptr RegionPoisonedAddr;
  RANGE_CHECK(__s, __maxlen, RegionInOutEnclaveStatus, RegionPoisonedAddr,
              true);
  va_list ap;
  va_start(ap, __format);
  int res = REAL(vsnprintf)(__s, __maxlen, __format, ap);
  va_end(ap);
  return res;
}
