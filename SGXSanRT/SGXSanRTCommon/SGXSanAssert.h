#pragma once
#include "SGXSanLog.hpp"

#define sgxsan_assert(cond) sgxsan_error(!(cond), "Assert Fail: " #cond "\n");