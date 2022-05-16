#pragma once

#include "SGXSanInt.h"
#include <stdint.h>

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal = true, const char *msg = "");

void PrintErrorAndAbort(const char *format, ...);

void sgxsan_warning_detail(bool cond, const char *message, uint64_t addr, uint64_t size);