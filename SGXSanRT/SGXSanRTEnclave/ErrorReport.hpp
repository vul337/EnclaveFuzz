#ifndef ERROR_REPORT_HPP
#define ERROR_REPORT_HPP

#include "SGXSanInt.h"

#define SGXSAN_ELRANGE_CHECK_BEG(start, is_write, size)                       \
    do                                                                        \
    {                                                                         \
        uptr _start = (uptr)start;                                            \
        uptr _end = _start + size - 1;                                        \
        if (_start > _end)                                                    \
        {                                                                     \
            GET_CALLER_PC_BP_SP;                                              \
            ReportGenericError(pc, bp, sp, _start, is_write, size, true);     \
        }                                                                     \
        uptr _enclave_end = g_enclave_base + g_enclave_size - 1;              \
        if (_end >= g_enclave_base && _start <= _enclave_end)                 \
        {                                                                     \
            if (_start < g_enclave_base or _end > _enclave_end)               \
            {                                                                 \
                GET_CALLER_PC_BP_SP;                                          \
                ReportGenericError(pc, bp, sp, _start, is_write, size, true); \
            }

#define SGXSAN_ELRANGE_CHECK_END \
    }                            \
    }                            \
    while (0)

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal);
#endif //ERROR_REPORT_HPP