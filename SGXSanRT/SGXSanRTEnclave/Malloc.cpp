
#include <unordered_set>
#include <pthread.h>
#include "SGXSanManifest.h"
#include "PoisonCheck.hpp"
#include "Malloc.hpp"
#include "Poison.hpp"
#include "ErrorReport.hpp"
#include "SGXSanRT.hpp"
#include "Quarantine.hpp"
#include "InternDlmalloc.hpp"

#if (USE_SGXSAN_MALLOC)
#define MALLOC sgxsan_malloc
#define BACKEND_MALLOC malloc
#define FREE sgxsan_free
#define BACKEND_FREE free
#define CALLOC sgxsan_calloc
#define BACKEND_CALLOC calloc
#define REALLOC sgxsan_realloc
#define BACKEND_REALLOC realloc
#else
#define MALLOC malloc
#define BACKEND_MALLOC dlmalloc
#define FREE free
#define BACKEND_FREE dlfree
#define CALLOC calloc
#define BACKEND_CALLOC dlcalloc
#define REALLOC realloc
#define BACKEND_REALLOC dlrealloc
#endif

#if (CHECK_MALLOC_FREE_MATCH)
static pthread_rwlock_t rwlock_heap_obj_user_beg_set = PTHREAD_RWLOCK_INITIALIZER;

#if (!USE_SGXSAN_MALLOC)
// Use SGXSan::DLAllocator avoid malloc-new-malloc's like infinitive loop
// there are two mempool never free, dwarf_reg_state_pool and dwarf_cie_info_pool
static std::unordered_set<uptr, std::hash<uptr>, std::equal_to<uptr>, SGXSan::ContainerAllocator<uptr>> heap_obj_user_beg_set;
#else
static std::unordered_set<uptr> heap_obj_user_beg_set;
#endif

#endif

struct chunk
{
  uptr alloc_beg;
  size_t user_size;
};

void *MALLOC(size_t size)
{
  if (not asan_inited)
  {
    return BACKEND_MALLOC(size);
  }

  uptr alignment = SHADOW_GRANULARITY;

  if (size == 0)
  {
    return nullptr;
  }

  uptr rz_size = ComputeRZSize(size);
  uptr rounded_size = RoundUpTo(size, alignment);
  uptr needed_size = rounded_size + 2 * rz_size;

  void *allocated = BACKEND_MALLOC(needed_size);

  if (allocated == nullptr)
  {
    return nullptr;
  }

  uptr alloc_beg = reinterpret_cast<uptr>(allocated);
  // If dlmalloc doesn't return an aligned memory, it's troublesome.
  // If it is so, we start to posion from RoundUpTo(allocated)
  assert(IsAligned(alloc_beg, alignment) && "here I want to see whether dlmalloc return an unaligned memory");
  uptr alloc_end = alloc_beg + needed_size;

  uptr user_beg = alloc_beg + rz_size;
  if (!IsAligned(user_beg, alignment))
    user_beg = RoundUpTo(user_beg, alignment);
  uptr user_end = user_beg + size;
  CHECK_LE(user_end, alloc_end);

  // place the chunk in left redzone
  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = reinterpret_cast<chunk *>(chunk_beg);

  // if alloc_beg is not aligned, we cannot automatically calculate it
  m->alloc_beg = alloc_beg;
  m->user_size = size;

  // printf("\n[malloc] alloc_beg=0x%lx user_beg=0x%lx\n", alloc_beg, user_beg);

  // start poisoning
  // if assume alloc_beg is 8-byte aligned, we can use FastPoisonShadow()
  /* Fast */ PoisonShadow(alloc_beg, user_beg - alloc_beg, kAsanHeapLeftRedzoneMagic);
  PoisonShadow(user_beg, size, 0x0); // user_beg is already aligned to alignment
  uptr right_redzone_beg = RoundUpTo(user_end, alignment);
  /* Fast */ PoisonShadow(right_redzone_beg, alloc_end - right_redzone_beg, kAsanHeapRightRedzoneMagic);

  // printf("[heap_obj_user_beg_set] [before malloc] ");
  // for (uptr p : heap_obj_user_beg_set)
  // {
  //     printf(" %lx", p);
  // }
  // printf(" %s", "\n");

  // record user_beg avoid user passing incorrect addr to free
  // I assume dlmalloc will not alloc an memory that already allocated
  // also assume thread safety implemented by dlmalloc, then alloc_beg never be the same for multi-threads
  // fix-me: is container thread-safe? (https://en.cppreference.com/w/cpp/container)
#if (CHECK_MALLOC_FREE_MATCH)
  pthread_rwlock_wrlock(&rwlock_heap_obj_user_beg_set);
  if (heap_obj_user_beg_set.find(user_beg) == heap_obj_user_beg_set.end())
  {
    heap_obj_user_beg_set.insert(user_beg);
    pthread_rwlock_unlock(&rwlock_heap_obj_user_beg_set);
  }
  else
  {
    pthread_rwlock_unlock(&rwlock_heap_obj_user_beg_set);
    ReportErrorInfo("malloc an already allocated memory");
  }
#endif
  // printf("[heap_obj_user_beg_set] [after malloc] ");
  // for (uptr p : heap_obj_user_beg_set)
  // {
  //     printf(" %lx", p);
  // }
  // printf(" %s", "\n");

  return reinterpret_cast<void *>(user_beg);
}

void FREE(void *ptr)
{
  if (not asan_inited)
  {
    BACKEND_FREE(ptr);
    return;
  }

  uptr user_beg = reinterpret_cast<uptr>(ptr);
  uptr alignment = SHADOW_GRANULARITY;
  CHECK(IsAligned(user_beg, alignment));

  // printf("[heap_obj_user_beg_set] [before free] ");
  // for (uptr p : heap_obj_user_beg_set)
  // {
  //     printf(" %lx", p);
  // }
  // printf(" %s", "\n");
#if (CHECK_MALLOC_FREE_MATCH)
  pthread_rwlock_wrlock(&rwlock_heap_obj_user_beg_set);
  if (heap_obj_user_beg_set.find(user_beg) == heap_obj_user_beg_set.end())
  {
    pthread_rwlock_unlock(&rwlock_heap_obj_user_beg_set);
    ReportErrorInfo("free an non-recorded address"); // abort();
  }
  else
  {
    heap_obj_user_beg_set.erase(user_beg);
    pthread_rwlock_unlock(&rwlock_heap_obj_user_beg_set);
  }
#endif
  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = reinterpret_cast<chunk *>(chunk_beg);
  size_t user_size = m->user_size;
  // printf("\n[recycle] alloc_beg=0x%lx user_beg=0x%lx\n", m->alloc_beg, user_beg);
  FastPoisonShadow(user_beg, RoundUpTo(user_size, alignment), kAsanHeapFreeMagic);

  QuarantineElement qe = {
      .alloc_beg = m->alloc_beg,
      .alloc_size = ComputeRZSize(user_size) * 2 + RoundUpTo(user_size, alignment),
      .user_beg = user_beg,
      .user_size = user_size};
  g_quarantine_cache->put(qe);

  // printf("[heap_obj_user_beg_set] [after free] ");
  // for (uptr p : heap_obj_user_beg_set)
  // {
  //     printf(" %lx", p);
  // }
  // printf(" %s", "\n");
}

void *CALLOC(size_t n_elements, size_t elem_size)
{
  if (not asan_inited)
  {
    return BACKEND_CALLOC(n_elements, elem_size);
  }

  if (n_elements == 0 || elem_size == 0)
  {
    return nullptr;
  }
  size_t req = n_elements * elem_size;
  if (req / n_elements != elem_size)
  {
    return nullptr;
  }
  void *mem = MALLOC(req);
  if (mem != nullptr)
  {
    memset(mem, 0, req);
  }
  return mem;
}

void *REALLOC(void *oldmem, size_t bytes)
{
  if (not asan_inited)
  {
    return BACKEND_REALLOC(oldmem, bytes);
  }

  void *mem = 0;
  if (oldmem == nullptr)
  {
    return MALLOC(bytes);
  }
  if (bytes == 0)
  {
    FREE(oldmem);
    return nullptr;
  }

  mem = MALLOC(bytes);

  if (mem != 0)
  {
    uptr chunk_beg = reinterpret_cast<uptr>(oldmem) - sizeof(chunk);
    chunk *m = reinterpret_cast<chunk *>(chunk_beg);
    size_t old_size = m->user_size;

    memcpy(mem, oldmem, bytes > old_size ? old_size : bytes);
    FREE(oldmem);
  }

  return mem;
}