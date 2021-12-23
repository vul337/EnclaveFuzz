#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "SGXSanPrintf.hpp"
#include "SGXSanRTTBridge.hpp"

/*
 * sgxsan_printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int sgxsan_printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    sgxsan_ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}