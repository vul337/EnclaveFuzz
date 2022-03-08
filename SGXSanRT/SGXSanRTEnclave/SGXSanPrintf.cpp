#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <string>
#include <mbusafecrt.h>
#include "SGXSanPrintf.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SGXInternal.hpp"
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
    uint64_t shadow_addr = ((((uint64_t)ptr - g_enclave_base) >> 3) + 0x7fff8000);
    sgxsan_printf("[0x%lx]: 0x%x\n", shadow_addr, *(uint8_t *)shadow_addr);
}