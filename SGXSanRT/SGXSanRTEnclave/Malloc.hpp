#pragma once

#include "SGXSanCheck.h"
#include "SGXSanDefs.h"
#include "SGXSanInt.h"
#include "SGXSanManifest.h"
#include <stddef.h>

#if (USE_SGXSAN_MALLOC)
#define MALLOC sgxsan_malloc
#define BACKEND_MALLOC malloc
#define FREE sgxsan_free
#define BACKEND_FREE free
#define CALLOC sgxsan_calloc
#define BACKEND_CALLOC calloc
#define REALLOC sgxsan_realloc
#define BACKEND_REALLOC realloc
#define MALLOC_USABLE_SZIE sgxsan_malloc_usable_size
extern size_t (*real_malloc_usable_size)(void *);
#define BACKEND_MALLOC_USABLE_SZIE real_malloc_usable_size
#else
// use our malloc series (which use dlmalloc as backend), and override original
// dlmalloc and tcmalloc libraries
#define MALLOC malloc
#define BACKEND_MALLOC dlmalloc
#define FREE free
#define BACKEND_FREE dlfree
#define CALLOC calloc
#define BACKEND_CALLOC dlcalloc
#define REALLOC realloc
#define BACKEND_REALLOC dlrealloc
#define MALLOC_USABLE_SZIE malloc_usable_size
#define BACKEND_MALLOC_USABLE_SZIE dlmalloc_usable_size
#endif

// rz_log represent 2^(rz_log+4)
static inline uptr ComputeRZLog(uptr user_requested_size) {
  u32 rz_log = user_requested_size <= 64 - 16            ? 0
               : user_requested_size <= 128 - 32         ? 1
               : user_requested_size <= 512 - 64         ? 2
               : user_requested_size <= 4096 - 128       ? 3
               : user_requested_size <= (1 << 14) - 256  ? 4
               : user_requested_size <= (1 << 15) - 512  ? 5
               : user_requested_size <= (1 << 16) - 1024 ? 6
                                                         : 7;

  return rz_log;
}

static inline u32 RZLog2Size(u32 rz_log) {
  CHECK_LT(rz_log, 8);
  return 16 << rz_log;
}

static inline uptr ComputeRZSize(uptr size) { return 16 << ComputeRZLog(size); }

#if defined(__cplusplus)
extern "C" {
#endif
void update_heap_usage(void *ptr, size_t (*malloc_usable_size_func)(void *mem),
                       bool true_add_false_minus = true);
void init_real_malloc_usable_size();
#if (USE_SGXSAN_MALLOC)
void *sgxsan_malloc(size_t size);
void sgxsan_free(void *ptr);
void *sgxsan_calloc(size_t n_elements, size_t elem_size);
void *sgxsan_realloc(void *oldmem, size_t bytes);
size_t sgxsan_malloc_usable_size(void *mem);
#else
size_t malloc_usable_size(void *mem);
#endif
#if defined(__cplusplus)
}
#endif
