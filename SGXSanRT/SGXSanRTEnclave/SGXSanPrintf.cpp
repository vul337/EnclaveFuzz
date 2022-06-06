#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <string>
#include <mbusafecrt.h>
#include "SGXSanPrintf.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SGXInternal.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanLog.hpp"
#include "SGXSanManifest.h"

static const char *log_level_to_prefix[] = {
    [LOG_LEVEL_NONE] = "",
    [LOG_LEVEL_ERROR] = "[SGXSan error] ",
    [LOG_LEVEL_WARNING] = "[SGXSan warning] ",
    [LOG_LEVEL_DEBUG] = "[SGXSan debug] ",
    [LOG_LEVEL_TRACE] = "[SGXSan trace] ",
};

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...)
{
    if (ll > USED_LOG_LEVEL)
        return;

    char buf[BUFSIZ] = {'\0'};
    std::string prefix = "";
    if (with_prefix)
    {
#if (SHOW_TID)
        snprintf(buf, BUFSIZ, "[TCSAsID=0x%p] ", get_tcs());
        prefix += buf;
#endif
        prefix += log_level_to_prefix[ll];
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    std::string content = (prefix + buf) + "\n";

    sgxsan_ocall_print_string(content.c_str());
}

/*
 * sgxsan_printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int sgxsan_printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    sgxsan_ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void print_shadow(void *ptr)
{
    uint64_t shadow_addr = MEM_TO_SHADOW((uint64_t)ptr);
    log_debug("[0x%lx =Shadow=> 0x%lx =Value=> 0x%x]\n", ptr, shadow_addr, *(uint8_t *)shadow_addr);
}

void print_ptr(char *info, uint64_t addr, uint64_t size)
{
    assert(addr && size);
    uint64_t shadow_addr = MEM_TO_SHADOW(addr);
    log_debug("%s\n[Addr: 0x%lx(0x%lx) =Shadow=> 0x%lx]\n", info, addr, size, shadow_addr);
}

void print_arg(char *info, uint64_t func_addr, int64_t pos)
{
    log_debug("%s\n[Arg: 0x%lx(%ld)]\n", info, func_addr, pos);
}