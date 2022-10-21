#pragma once
#include "SGXSanManifest.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

enum log_level {
  LOG_LEVEL_NONE,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_TRACE,
};

#define log_always(...) sgxsan_log(LOG_LEVEL_NONE, true, __VA_ARGS__)
#define log_error(...) sgxsan_log(LOG_LEVEL_ERROR, true, __VA_ARGS__)
#define log_warning(...) sgxsan_log(LOG_LEVEL_WARNING, true, __VA_ARGS__)
#define log_debug(...) sgxsan_log(LOG_LEVEL_DEBUG, true, __VA_ARGS__)
#define log_trace(...) sgxsan_log(LOG_LEVEL_TRACE, true, __VA_ARGS__)

// no prefix
#define log_always_np(...) sgxsan_log(LOG_LEVEL_NONE, false, __VA_ARGS__)
#define log_error_np(...) sgxsan_log(LOG_LEVEL_ERROR, false, __VA_ARGS__)
#define log_warning_np(...) sgxsan_log(LOG_LEVEL_WARNING, false, __VA_ARGS__)
#define log_debug_np(...) sgxsan_log(LOG_LEVEL_DEBUG, false, __VA_ARGS__)
#define log_trace_np(...) sgxsan_log(LOG_LEVEL_TRACE, false, __VA_ARGS__)

#ifndef USED_LOG_LEVEL
#define USED_LOG_LEVEL LOG_LEVEL_WARNING
#endif

#if defined(__cplusplus)
extern "C" {
#endif
void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...);
#ifdef IN_ENCLAVE
void sgxsan_print_stack_trace(log_level ll = LOG_LEVEL_ERROR);
#endif
#if defined(__cplusplus)
}
#endif

#ifdef IN_ENCLAVE
#define sgxsan_error(cond, ...)                                                \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_error(__VA_ARGS__);                                                  \
      sgxsan_print_stack_trace();                                              \
      abort();                                                                 \
    }                                                                          \
  } while (0);
#else
#define sgxsan_error(cond, ...)                                                \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_error(__VA_ARGS__);                                                  \
      abort();                                                                 \
    }                                                                          \
  } while (0);
#endif

#ifdef IN_ENCLAVE
#define sgxsan_warning(cond, ...)                                              \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_warning(__VA_ARGS__);                                                \
      sgxsan_print_stack_trace();                                              \
    }                                                                          \
  } while (0);
#else
#define sgxsan_warning(cond, ...)                                              \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_warning(__VA_ARGS__);                                                \
    }                                                                          \
  } while (0);
#endif
