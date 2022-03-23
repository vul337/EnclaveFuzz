#ifndef SGXSAN_PRINTF_HPP
#define SGXSAN_PRINTF_HPP

#ifndef PRINTF
#define PRINTF sgxsan_printf
#endif

#include <stdint.h>

#if defined(__cplusplus)
extern "C"
{
#endif
    int sgxsan_printf(const char *fmt, ...);
    void print_shadow(void *ptr);
    void print_ptr(char *info, uint64_t addr, uint64_t size);
    void print_arg(char *info, uint64_t func_addr, int64_t pos);
#if defined(__cplusplus)
}
#endif

#endif