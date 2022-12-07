#pragma once

#include "SGXSanRTConfig.h"
#include <dlfcn.h>
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>

/* Page assumption */
#define PAGE_SIZE 0x1000
#define PAGE_SIZE_SHIFT 12

/// Shadow basic settings
#ifndef SHADOW_OFFSET
#define SHADOW_OFFSET 0x7fff8000
#endif
#define X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS 47
#define SHADOW_SCALE 3
#define ADDR_SPACE_BITS X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS
#define SHADOW_GRANULARITY (1UL << SHADOW_SCALE)
#define SHADOW_SIZE (1UL << (ADDR_SPACE_BITS - SHADOW_SCALE))

#define MEM_TO_SHADOW(mem) (((uptr)(mem) >> SHADOW_SCALE) + SHADOW_OFFSET)

/// Some
typedef unsigned long uptr;
typedef signed long sptr;

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#define GET_CALLER_PC_BP_SP                                                    \
  uptr pc = (uptr)__builtin_return_address(0);                                 \
  uptr bp = (uptr)__builtin_frame_address(0);                                  \
  uptr local_stack;                                                            \
  uptr sp = (uptr)&local_stack

/// mem layout
#define kLowMemBeg 0
#define kLowMemEnd (SHADOW_OFFSET - 1)
#define kLowShadowBeg SHADOW_OFFSET
#define kLowShadowEnd (MEM_TO_SHADOW(kLowShadowBeg) - 1)
#define kHighMemBeg (kLowShadowBeg + SHADOW_SIZE)
#define kHighMemEnd ((1UL << ADDR_SPACE_BITS) - 1)
#define kHighShadowBeg MEM_TO_SHADOW(kHighMemBeg)
#define kHighShadowEnd (kHighMemBeg - 1)
#define kShadowGapBeg (kLowShadowEnd + 1)
#define kShadowGapEnd (kHighShadowBeg - 1)

#define kLowShadowGuardBeg (kLowShadowBeg - PAGE_SIZE)
#define kLowShadowGuardEnd (kLowShadowBeg - 1)

#define kHighShadowGuardBeg (kHighShadowEnd + 1)
#define kHighShadowGuardEnd (kHighShadowEnd + PAGE_SIZE)
/// Init util
extern bool asan_inited;

/// Logging utils
enum log_level {
  LOG_LEVEL_ALWAYS,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_TRACE,
};

#ifndef USED_LOG_LEVEL
#define USED_LOG_LEVEL LOG_LEVEL_WARNING
#endif

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...);

/// have prefix in output
#define log_always(...) sgxsan_log(LOG_LEVEL_ALWAYS, true, __VA_ARGS__)
#define log_error(...) sgxsan_log(LOG_LEVEL_ERROR, true, __VA_ARGS__)
#define log_warning(...) sgxsan_log(LOG_LEVEL_WARNING, true, __VA_ARGS__)
#define log_debug(...) sgxsan_log(LOG_LEVEL_DEBUG, true, __VA_ARGS__)
#define log_trace(...) sgxsan_log(LOG_LEVEL_TRACE, true, __VA_ARGS__)

/// no prefix in output
#define log_always_np(...) sgxsan_log(LOG_LEVEL_ALWAYS, false, __VA_ARGS__)
#define log_error_np(...) sgxsan_log(LOG_LEVEL_ERROR, false, __VA_ARGS__)
#define log_warning_np(...) sgxsan_log(LOG_LEVEL_WARNING, false, __VA_ARGS__)
#define log_debug_np(...) sgxsan_log(LOG_LEVEL_DEBUG, false, __VA_ARGS__)
#define log_trace_np(...) sgxsan_log(LOG_LEVEL_TRACE, false, __VA_ARGS__)

void sgxsan_backtrace(log_level ll = LOG_LEVEL_ERROR);

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal = true,
                        const char *msg = "");

#define sgxsan_error(cond, ...)                                                \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_error(__VA_ARGS__);                                                  \
      sgxsan_backtrace();                                                      \
      abort();                                                                 \
    }                                                                          \
  } while (0);

#define sgxsan_assert(cond) sgxsan_error(!(cond), #cond "\n");

#define sgxsan_warning(cond, ...)                                              \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_warning(__VA_ARGS__);                                                \
      sgxsan_backtrace(LOG_LEVEL_WARNING);                                     \
    }                                                                          \
  } while (0);

/// Interceptor
#define SGXSAN(sym) sgxsan_##sym

/// mem tools
static inline bool AddrIsInLowMem(uptr a) {
  return kLowMemBeg <= a && a <= kLowMemEnd;
}

static inline bool AddrIsInHighMem(uptr a) {
  return kHighMemBeg <= a && a <= kHighMemEnd;
}

static inline bool AddrIsInMem(uptr a) {
  return AddrIsInLowMem(a) or AddrIsInHighMem(a);
}

static inline bool AddrIsInLowShadow(uptr a) {
  return kLowShadowBeg <= a && a <= kLowShadowEnd;
}

static inline bool AddrIsInHighShadow(uptr a) {
  return kHighShadowBeg <= a && a <= kHighShadowEnd;
}

static inline bool AddrIsInShadow(uptr a) {
  return AddrIsInLowShadow(a) or AddrIsInHighShadow(a);
}

static inline uptr MemToShadow(uptr addr) {
  sgxsan_error(not AddrIsInMem(addr), "Address not in valid memory\n");
  return MEM_TO_SHADOW(addr);
}

/// Alignment
static inline bool IsAligned(uptr a, uptr alignment) {
  return (a & (alignment - 1)) == 0;
}

static inline bool IsPowerOfTwo(uptr x) { return (x & (x - 1)) == 0; }

static inline uptr RoundUpTo(uptr size, uptr boundary) {
  sgxsan_error(not IsPowerOfTwo(boundary), "Boundary is not power of two\n");
  return (size + boundary - 1) & ~(boundary - 1);
}

static inline uptr RoundDownTo(uptr x, uptr boundary) {
  sgxsan_error(not IsPowerOfTwo(boundary), "Boundary is not power of two\n");
  return x & ~(boundary - 1);
}

static inline uptr RoundUpDiv(uptr a, uptr b) {
  sgxsan_error(not IsPowerOfTwo(b), "Boundary is not power of two\n");
  return (a + b - 1) / b;
}

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2) {
  return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}

static inline uptr ExtendInt8(uint8_t _8bit) {
  uptr result = 0;
  for (size_t i = 0; i < sizeof(uptr); i++) {
    result = (result << 8) + _8bit;
  }
  return result;
}

static inline int getArraySum(int *array, int size) {
  int sum = 0;
  for (int i = 0; i < size; i++) {
    sum += array[i];
  }
  return sum;
}

/// Cipher detect
void check_output_hybrid(uint64_t addr, uint64_t size);

void ClearSGXSanRT();

/* addr2line & backtrace Util */
std::string addr2fname_try(void *addr);
void *sgxsan_backtrace_i(int idx);

/* Set or get global Enclave file name */
void setEnclaveFileName(std::string fileName);
std::string getEnclaveFileName();

#if defined(__cplusplus)
extern "C" {
#endif
void register_sgxsan_sigaction();
int hook_enclave();
#if defined(__cplusplus)
}
#endif
