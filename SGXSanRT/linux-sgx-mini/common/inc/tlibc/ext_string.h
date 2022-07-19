#pragma once

#include <stddef.h>

/// glibc's \c string.h doesn't contain \c errno_t, while the one of sgxsdk dose
typedef int errno_t;

#ifdef __cplusplus
extern "C" {
#endif

/// glibc doesn't contain below
extern errno_t memset_s(void *s, size_t smax, int c, size_t n);
extern int consttime_memequal(const void *b1, const void *b2, size_t len);

#ifdef __cplusplus
}
#endif