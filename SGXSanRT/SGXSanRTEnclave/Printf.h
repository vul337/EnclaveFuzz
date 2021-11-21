#ifndef PRINTF_H
#define PRINTF_H
#if defined(__cplusplus)
extern "C"
{
#endif

    //if in enclave, printf is defined in Enclave.cpp
    extern int printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif
#endif