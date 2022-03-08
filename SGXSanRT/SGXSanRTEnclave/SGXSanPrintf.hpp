#ifndef SGXSAN_PRINTF_HPP
#define SGXSAN_PRINTF_HPP

#ifndef PRINTF
#define PRINTF sgxsan_printf
#endif

#if defined(__cplusplus)
extern "C"
{
#endif
    int sgxsan_printf(const char *fmt, ...);
    void print_shadow(void *ptr);
#if defined(__cplusplus)
}
#endif

#endif