
#include "Malloc.h"
#include "Poison.h"
#include <algorithm>
#include <string.h>
#include <unordered_set>

static QuarantineCache QCache;
QuarantineCache *gQCache = &QCache;

static pthread_mutex_t heap_usage_mutex = PTHREAD_MUTEX_INITIALIZER;
size_t global_heap_usage = 0;
const size_t kHeapObjectChunkMagic = 0xDEADBEEF;

struct chunk {
  size_t magic; // ensure queried user_beg is correct
  uptr alloc_beg;
  size_t alloc_size;
  size_t user_size;
};

void update_heap_usage(void *ptr, bool true_add_false_minus) {
#if (USED_LOG_LEVEL >= 3 /* LOG_LEVEL_DEBUG */)
  static uint64_t heapLogIndex = 0;
  if (ptr) {
    pthread_mutex_lock(&heap_usage_mutex);
    heapLogIndex++;
    size_t allocated_size = BACKEND_MALLOC_USABLE_SIZE(ptr);
    if (true_add_false_minus) {
      log_trace("(%ld)[HEAP SIZE] 0x%lx=0x%lx+0x%lx\n", heapLogIndex,
                global_heap_usage + allocated_size, global_heap_usage,
                allocated_size);
      global_heap_usage += allocated_size;
    } else {
      log_trace("(%ld)[HEAP SIZE] 0x%lx=0x%lx-0x%lx\n", heapLogIndex,
                global_heap_usage - allocated_size, global_heap_usage,
                allocated_size);
      global_heap_usage -= allocated_size;
    }
    pthread_mutex_unlock(&heap_usage_mutex);
  }
#else
  (void)ptr;
  (void)true_add_false_minus;
  (void)heap_usage_mutex;
#endif
}

void *MALLOC(size_t size) {
  if (size == 0) {
    sgxsan_warning(true, "Malloc 0 size\n");
    // return nullptr;
  }

  if (not asan_inited) {
    auto p = BACKEND_MALLOC(size);
    update_heap_usage(p);
    return p;
  }

  uptr alignment = SHADOW_GRANULARITY;

  uptr rz_size =
      std::max(ComputeRZSize(size), RoundUpTo(sizeof(chunk), alignment));
  uptr rounded_size = RoundUpTo(size, alignment);
  uptr needed_size = rounded_size + 2 * rz_size;

  void *allocated = BACKEND_MALLOC(needed_size);
  if (allocated == nullptr) {
    return nullptr;
  }
  update_heap_usage(allocated);

  size_t allocated_size = BACKEND_MALLOC_USABLE_SIZE(allocated);

  uptr alloc_beg = (uptr)allocated;
  // If real malloc doesn't return an aligned memory, it's troublesome.
  sgxsan_assert(IsAligned(alloc_beg, alignment));
  uptr alloc_end = alloc_beg + allocated_size;

  uptr user_beg = alloc_beg + rz_size;
  if (!IsAligned(user_beg, alignment))
    user_beg = RoundUpTo(user_beg, alignment);
  uptr user_end = user_beg + size;
  sgxsan_assert(user_end <= alloc_end);

  // place the chunk in left redzone
  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = (chunk *)chunk_beg;

  m->magic = kHeapObjectChunkMagic;
  m->alloc_beg = alloc_beg;
  m->alloc_size = allocated_size;
  m->user_size = size;
  log_trace("\n");
  log_trace("[Malloc] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", alloc_beg, user_beg,
            user_end, alloc_end);

  PoisonShadow(alloc_beg, user_beg - alloc_beg, kAsanHeapLeftRedzoneMagic);
  sgxsan_assert(IsAligned(user_beg, alignment));
  PoisonShadow(user_beg, size, kAsanNotPoisonedMagic);
  uptr right_redzone_beg = RoundUpTo(user_end, alignment);
  PoisonShadow(right_redzone_beg, alloc_end - right_redzone_beg,
               kAsanHeapRightRedzoneMagic);

  return (void *)user_beg;
}

void FREE(void *ptr) {
  if (not asan_inited) {
    update_heap_usage(ptr, false);
    BACKEND_FREE(ptr);
    return;
  }
  if (ptr == nullptr)
    return;

  uptr user_beg = (uptr)ptr;
  if (*(uint8_t *)MEM_TO_SHADOW(user_beg) == kAsanHeapFreeMagic) {
    GET_CALLER_PC_BP_SP;
    ReportGenericError(pc, bp, sp, user_beg, 0, 1, true, "Double Free");
  }
  uptr alignment = SHADOW_GRANULARITY;
  sgxsan_assert(IsAligned(user_beg, alignment));

  chunk *m = (chunk *)(user_beg - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  log_trace("\n");
  log_trace("[Recycle] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", m->alloc_beg, user_beg,
            user_beg + m->user_size, m->alloc_beg + m->alloc_size);
  PoisonShadow(user_beg, RoundUpTo(m->user_size, alignment),
               kAsanHeapFreeMagic);

  QuarantineElement qe = {.alloc_beg = m->alloc_beg,
                          .alloc_size = m->alloc_size,
                          .user_beg = user_beg,
                          .user_size = m->user_size};
  gQCache->put(qe);
}

void *CALLOC(size_t n_elements, size_t elem_size) {
  if (not asan_inited) {
    return BACKEND_CALLOC(n_elements, elem_size);
  }

  size_t req = n_elements * elem_size;
  if (req == 0) {
    sgxsan_warning(true, "Calloc 0 size\n");
    return nullptr;
  }
  sgxsan_assert(req / n_elements == elem_size);
  void *mem = MALLOC(req);
  if (mem != nullptr) {
    memset(mem, 0, req);
  }
  return mem;
}

void *REALLOC(void *oldmem, size_t bytes) {
  if (not asan_inited) {
    return BACKEND_REALLOC(oldmem, bytes);
  }

  if (oldmem == nullptr) {
    return MALLOC(bytes);
  }
  chunk *m = (chunk *)((uptr)oldmem - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  if (bytes == 0) {
    FREE(oldmem);
    return nullptr;
  }

  void *mem = MALLOC(bytes);

  if (mem != nullptr) {
    memcpy(mem, oldmem, std::min(m->user_size, bytes));
    FREE(oldmem);
  }

  return mem;
}

size_t MALLOC_USABLE_SIZE(void *mem) {
  chunk *m = (chunk *)((uptr)mem - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  return m->user_size;
}
