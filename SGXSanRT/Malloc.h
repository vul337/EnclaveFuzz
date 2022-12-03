#pragma once

#include "Poison.h"
#include "SGXSanRT.h"
#include <deque>
#include <pthread.h>
#include <stddef.h>
#include <sys/resource.h>

#define FRONT_END(sym) sym
#define BACK_END(sym) back_end_##sym

#define MALLOC FRONT_END(malloc)
#define BACKEND_MALLOC BACK_END(malloc)
#define FREE FRONT_END(free)
#define BACKEND_FREE BACK_END(free)
#define CALLOC FRONT_END(calloc)
#define BACKEND_CALLOC BACK_END(calloc)
#define REALLOC FRONT_END(realloc)
#define BACKEND_REALLOC BACK_END(realloc)
#define MALLOC_USABLE_SIZE FRONT_END(malloc_usable_size)
#define BACKEND_MALLOC_USABLE_SIZE BACK_END(malloc_usable_size)

#define DECLARE_BACK_END(sym) extern decltype(sym) *BACK_END(sym)
DECLARE_BACK_END(malloc);
DECLARE_BACK_END(free);
DECLARE_BACK_END(calloc);
DECLARE_BACK_END(realloc);
DECLARE_BACK_END(malloc_usable_size);

#if defined(__cplusplus)
extern "C" {
#endif
void *__libc_malloc(size_t size) throw();
void __libc_free(void *ptr) throw();
void *__libc_calloc(size_t nmemb, size_t size) throw();
void *__libc_realloc(void *ptr, size_t size) throw();
void updateBackEndHeapAllocator();
void *MALLOC(size_t size);
void FREE(void *ptr);
void *CALLOC(size_t n_elements, size_t elem_size);
void *REALLOC(void *oldmem, size_t bytes);
size_t MALLOC_USABLE_SIZE(void *mem);
#if defined(__cplusplus)
}
#endif

// rz_log represent 2^(rz_log+4)
static inline uptr ComputeRZLog(uptr user_requested_size) {
  uint32_t rz_log = user_requested_size <= 64 - 16            ? 0
                    : user_requested_size <= 128 - 32         ? 1
                    : user_requested_size <= 512 - 64         ? 2
                    : user_requested_size <= 4096 - 128       ? 3
                    : user_requested_size <= (1 << 14) - 256  ? 4
                    : user_requested_size <= (1 << 15) - 512  ? 5
                    : user_requested_size <= (1 << 16) - 1024 ? 6
                                                              : 7;

  return rz_log;
}

static inline uint32_t RZLog2Size(uint32_t rz_log) {
  sgxsan_error(rz_log >= 8, "rz_log>= 8\n");
  return 16 << rz_log;
}

static inline uptr ComputeRZSize(uptr size) { return 16 << ComputeRZLog(size); }

void update_heap_usage(void *ptr, bool true_add_false_minus = true);

template <class T> class ContainerAllocator {
public:
  // type definitions
  typedef T value_type;
  typedef T *pointer;
  typedef const T *const_pointer;
  typedef T &reference;
  typedef const T &const_reference;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;

  // rebind allocator to type U
  template <class U> struct rebind { typedef ContainerAllocator<U> other; };

  // return address of values
  pointer address(reference value) const { return &value; }
  const_pointer address(const_reference value) const { return &value; }

  /* constructors and destructor
   * - nothing to do because the allocator has no state
   */
  ContainerAllocator() noexcept {}
  ContainerAllocator(const ContainerAllocator &) noexcept {}
  template <class U>
  ContainerAllocator(const ContainerAllocator<U> &) noexcept {}
  ~ContainerAllocator() noexcept {}

  // return maximum number of elements that can be allocated
  size_type max_size() const noexcept { return size_type(~0) / sizeof(T); }

  // allocate but don't initialize num elements of type T
  pointer allocate(size_type num, const void * = 0) {
    sgxsan_assert(num <= max_size());
    pointer ret = (pointer)(BACKEND_MALLOC(num * sizeof(T)));
    update_heap_usage(ret);
    sgxsan_assert(ret != nullptr);
    return ret;
  }

  // initialize elements of allocated storage p with value value
  void construct(pointer p, const T &value) {
    // initialize memory with placement new
    new ((void *)p) T(value);
  }

  // destroy elements of initialized storage p
  void destroy(pointer p) {
    // destroy objects by calling their destructor
    p->~T();
  }

  // deallocate storage p of deleted elements
  void deallocate(pointer p, size_type num) {
    (void)num;
    if (p) {
      update_heap_usage((void *)p, false);
      BACKEND_FREE((void *)p);
    }
  }
};

// return that all specializations of this allocator are interchangeable
template <class T1, class T2>
bool operator==(const ContainerAllocator<T1> &,
                const ContainerAllocator<T2> &) throw() {
  return true;
}
template <class T1, class T2>
bool operator!=(const ContainerAllocator<T1> &,
                const ContainerAllocator<T2> &) throw() {
  return false;
}

struct QuarantineElement {
  uptr alloc_beg;
  uptr alloc_size;
  uptr user_beg;
  uptr user_size;
};

// Use SGXSan::ContainerAllocator(BACKEND_MALLOC series as backend) avoid
// malloc-new-malloc's like infinitive loop
typedef std::deque<QuarantineElement, ContainerAllocator<QuarantineElement>>
    QuarantineQueueTy;

#define SGXSAN_MAX_QUARANTINE_SIZE 0x10000000

class QuarantineCache {
public:
  QuarantineCache() {
    auto p = BACKEND_MALLOC(sizeof(QuarantineQueueTy));
    sgxsan_assert(p != nullptr);
    update_heap_usage(p);
    m_queue = new (p) QuarantineQueueTy();
    sgxsan_assert(m_queue != nullptr);
    m_mutex = PTHREAD_MUTEX_INITIALIZER;
    m_used_size = 0;
    // Calculate suitable quarantine size
    struct rlimit64 limit64;
    sgxsan_assert(getrlimit64(RLIMIT_DATA, &limit64) == 0);
    struct rlimit limit;
    sgxsan_assert(getrlimit(RLIMIT_DATA, &limit) == 0);
    m_max_size = std::min(std::min(limit64.rlim_cur, limit.rlim_cur) >> 4,
                          (size_t)SGXSAN_MAX_QUARANTINE_SIZE);
  }

  ~QuarantineCache() {
    sgxsan_assert(m_queue != nullptr);
    // free memory recorded in Quarantine, not only the struct that record
    // Quarantine
    while (not empty())
      freeOldestQuarantineElement();
    // free struct that record Quarantine
    m_queue->~deque();
    update_heap_usage(m_queue, false);
    BACKEND_FREE(m_queue);
    m_queue = nullptr;
    m_used_size = 0;
    m_max_size = 0;
  }

  void put(QuarantineElement qe) {
    pthread_mutex_lock(&m_mutex);
    if (m_queue == nullptr) {
      freeDirectly(qe);
      goto out;
    }

    if (m_queue->empty()) {
      sgxsan_assert(m_used_size == 0);
    }

    // if cache can not hold this element, directly free it
    if (qe.alloc_size > m_max_size) {
      freeDirectly(qe);
    } else {
      // pop queue util it can hold new element
      while (UNLIKELY((!m_queue->empty()) &&
                      (m_used_size + qe.alloc_size > m_max_size))) {
        freeOldestQuarantineElement();
        if (m_queue->empty()) {
          sgxsan_assert(m_used_size == 0);
        }
      }
      log_trace("[Put to Quaratine] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n",
                qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size,
                qe.alloc_beg + qe.alloc_size);
      m_queue->push_back(qe);
      m_used_size += qe.alloc_size;
    }
  out:
    pthread_mutex_unlock(&m_mutex);
  }

private:
  void freeQuarantineElement(QuarantineElement qe) {
    update_heap_usage((void *)qe.alloc_beg, false);
    BACKEND_FREE(reinterpret_cast<void *>(qe.alloc_beg));
    log_trace("[Free QuarantineElement] [0x%lx..0x%lx ~ 0x%lx..0x%lx) \n",
              qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size,
              qe.alloc_beg + qe.alloc_size);
    PoisonShadow(qe.alloc_beg, qe.alloc_size, kAsanHeapLeftRedzoneMagic, true);
    // update quarantine cache
    sgxsan_assert(m_used_size >= qe.alloc_size);
    m_used_size -= qe.alloc_size;
  }
  void freeDirectly(QuarantineElement qe) {
    update_heap_usage((void *)qe.alloc_beg, false);
    BACKEND_FREE((void *)qe.alloc_beg);
    log_trace("[Direct Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg,
              qe.user_beg, qe.user_beg + qe.user_size,
              qe.alloc_beg + qe.alloc_size);
    FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, SHADOW_GRANULARITY),
                     kAsanHeapLeftRedzoneMagic);
  }
  void freeOldestQuarantineElement() {
    QuarantineElement front_qe = m_queue->front();
    // free and poison
    freeQuarantineElement(front_qe);
    m_queue->pop_front();
  }
  bool empty() { return m_queue->empty(); }

  QuarantineQueueTy *m_queue;
  size_t m_used_size;
  size_t m_max_size;
  pthread_mutex_t m_mutex;
};

extern QuarantineCache *gQCache;
