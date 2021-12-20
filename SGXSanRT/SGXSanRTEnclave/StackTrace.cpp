#include <stdint.h>
#include <sgx_error.h>
#include <sgx_defs.h>
#include "SGXSanPrintf.hpp"
#include "SGXSanCommonPoisonCheck.hpp"
#include "SGXSanStackTrace.hpp"

extern "C" sgx_status_t SGX_CDECL sgxsan_ocall_addr2line(uint64_t addr, int level);

void sgxsan_print_stack_trace(int level)
{
    PRINTF("======= Stack Trace Begin =======\n");
    uint64_t ret_addr = (uint64_t)__builtin_return_address(0);
    uint64_t bp = (uint64_t)__builtin_frame_address(0);
    for (int i = 0;; i++)
    {
        // PRINTF("ret_addr = %p\tbp = %p\n", ret_addr, bp);
        if (i >= level)
        {
            sgxsan_ocall_addr2line(ret_addr - g_enclave_base - 1, i);
        }
        bp = *(uint64_t *)bp;
        if (!is_addr_in_elrange(bp))
            break;
        ret_addr = *(uint64_t *)(bp + 8);
        if (!is_addr_in_elrange(ret_addr))
            break;
    }
    PRINTF("======== Stack Trace End ========\n");
}
