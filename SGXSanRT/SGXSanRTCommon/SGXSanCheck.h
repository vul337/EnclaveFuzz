#ifndef SGXSAN_CHECK_H
#define SGXSAN_CHECK_H

#include "SGXSanAssert.h"

#ifndef CHECK
#define CHECK_IMPL(c1, op, c2)                                                 \
  do {                                                                         \
    sgxsan_assert(c1 op c2);                                                   \
  } while (0)

#define CHECK(a) CHECK_IMPL((a), !=, 0)
#define CHECK_EQ(a, b) CHECK_IMPL((a), ==, (b))
#define CHECK_NE(a, b) CHECK_IMPL((a), !=, (b))
#define CHECK_LT(a, b) CHECK_IMPL((a), <, (b))
#define CHECK_LE(a, b) CHECK_IMPL((a), <=, (b))
#define CHECK_GT(a, b) CHECK_IMPL((a), >, (b))
#define CHECK_GE(a, b) CHECK_IMPL((a), >=, (b))
#endif

#endif