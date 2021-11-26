#pragma once

#include "SGXSanInt.h"

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal);

void PrintErrorAndAbort(const char *format, ...);
