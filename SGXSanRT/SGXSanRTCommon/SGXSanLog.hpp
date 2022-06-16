#pragma once
#include "SGXSanManifest.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

enum log_level
{
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
extern "C"
{
#endif
    void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...);
#ifdef IN_ENCLAVE
    void sgxsan_print_stack_trace(log_level ll = LOG_LEVEL_ERROR);
#endif
#if defined(__cplusplus)
}
#endif

static inline void sgxsan_error(bool cond, const char *fmt, ...)
{
    if (cond)
    {
        va_list ap;
        va_start(ap, fmt);
        log_error(fmt, ap);
        va_end(ap);
#ifdef IN_ENCLAVE
        sgxsan_print_stack_trace();
#endif
        abort();
    }
}

static inline void sgxsan_warning(bool cond, const char *fmt, ...)
{
    if (cond)
    {
        va_list ap;
        va_start(ap, fmt);
        log_warning(fmt, ap);
        va_end(ap);
#ifdef IN_ENCLAVE
        sgxsan_print_stack_trace();
#endif
    }
}
