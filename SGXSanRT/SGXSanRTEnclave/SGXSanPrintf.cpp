#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <string>
#include <mbusafecrt.h>
#include "SGXSanPrintf.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SGXInternal.hpp"
#include "SGXSanCommonShadowMap.hpp"
/*
 * sgxsan_printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int sgxsan_printf(const char *fmt, ...)
{
    // std::string str = "";
    char buf[BUFSIZ] = {'\0'};
    // sprintf_s(buf, BUFSIZ, "[TID 0x%llx] ", (uint64_t)get_tcs());
    // str += buf;
    // memset(buf, 0, BUFSIZ);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    // str += buf;
    // sgxsan_ocall_print_string(str.c_str());
    sgxsan_ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void print_shadow(void *ptr)
{
    uint64_t shadow_addr = MEM_TO_SHADOW((uint64_t)ptr);
    PRINTF("[0x%lx =Shadow=> 0x%lx =Value=> 0x%x]\n", ptr, shadow_addr, *(uint8_t *)shadow_addr);
}

void print_ptr(char *info, uint64_t addr, uint64_t size)
{
    assert(addr && size);
    uint64_t shadow_addr = MEM_TO_SHADOW(addr);
    PRINTF("%s\n[Addr: 0x%lx(0x%lx) =Shadow=> 0x%lx]\n", info, addr, size, shadow_addr);
}

void print_arg(char *info, uint64_t func_addr, int64_t pos)
{
    PRINTF("%s\n[Arg: 0x%lx(%ld)]\n", info, func_addr, pos);
}