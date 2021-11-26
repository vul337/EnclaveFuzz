#pragma once

#include <stdint.h>

extern "C" void sgxsan_user_check(uint64_t ptr, uint64_t len);
