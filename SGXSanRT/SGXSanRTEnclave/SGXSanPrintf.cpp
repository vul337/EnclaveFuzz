#include "SGXSanPrintf.hpp"
#include "SGXInternal.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanLog.hpp"
#include "SGXSanManifest.h"
#include "SGXSanRTTBridge.hpp"
#include <mbusafecrt.h>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <string>

static const char *log_level_to_prefix[] = {
    [LOG_LEVEL_NONE] = "",
    [LOG_LEVEL_ERROR] = "[SGXSan error] ",
    [LOG_LEVEL_WARNING] = "[SGXSan warning] ",
    [LOG_LEVEL_DEBUG] = "[SGXSan debug] ",
    [LOG_LEVEL_TRACE] = "[SGXSan trace] ",
};

// can't call malloc, since malloc may call this function
void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (ll > USED_LOG_LEVEL)
    return;

  char buf[BUFSIZ] = {'\0'};
  size_t offset = 0;
  if (with_prefix) {
#if (SHOW_TID)
    snprintf(buf, BUFSIZ, "[TCSAsID=0x%p] ", get_tcs());
#endif
    const char *prefix = log_level_to_prefix[ll];
    offset = strlen(buf);
    sgxsan_assert(strlen(prefix) < BUFSIZ - offset);
    strcat_s(buf + offset, BUFSIZ - offset, prefix);
  }

  va_list ap;
  va_start(ap, fmt);
  offset = strlen(buf);
  vsnprintf(buf + offset, BUFSIZ - offset, fmt, ap);
  va_end(ap);

  sgxsan_ocall_print_string(buf);
}

/*
 * sgxsan_printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int sgxsan_printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  sgxsan_ocall_print_string(buf);
  return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void print_shadow(void *ptr) {
  uint64_t shadow_addr = MEM_TO_SHADOW((uint64_t)ptr);
  log_trace("[0x%lx =Shadow=> 0x%lx =Value=> 0x%x]\n", ptr, shadow_addr,
            *(uint8_t *)shadow_addr);
}

void print_ptr(char *info, uint64_t addr, uint64_t size) {
  sgxsan_assert(addr && size);
  uint64_t shadow_addr = MEM_TO_SHADOW(addr);
  log_trace("%s\n[Addr: 0x%lx(0x%lx) =Shadow=> 0x%lx]\n", info, addr, size,
            shadow_addr);
}

void print_arg(char *info, uint64_t func_addr, int64_t pos) {
  log_trace("%s\n[Arg: 0x%lx(%ld)]\n", info, func_addr, pos);
}