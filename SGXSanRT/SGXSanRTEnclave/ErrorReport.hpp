#pragma once

#include "SGXSanInt.h"
#include <stdint.h>

#define SGXSAN_WARNING_DETAIL(cond, message, addr, size)                       \
  do {                                                                         \
    if (cond) {                                                                \
      log_warning_np("================== Message ===================\n"        \
                     "[SGXSan Warning] %s \n",                                 \
                     message);                                                 \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, 0, size, false);                    \
    }                                                                          \
  } while (0);

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal = true,
                        const char *msg = "");
