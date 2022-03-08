#include "SGXSanPrintf.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanStackTrace.hpp"
#include "StackTrace.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SGXInternal.hpp"

// level == 0 means return address of function that called 'get_ret_addrs_in_stack'
void get_ret_addrs_in_stack(std::vector<uint64_t> &ret_addrs, uint64_t base_addr, int level)
{
    level += 1;
    uint64_t ret_addr = (uint64_t)__builtin_return_address(0);
    uint64_t bp = (uint64_t)__builtin_frame_address(0);
    for (int i = 0; i - level < 50; i++)
    {
        if (i >= level)
        {
            ret_addrs.emplace_back(ret_addr - base_addr);
        }
        bp = *(uint64_t *)bp;
        if (!is_addr_in_elrange(bp))
            break;
        ret_addr = *(uint64_t *)(bp + 8);
        if (!is_addr_in_elrange(ret_addr))
            break;
    }
}

void sgxsan_print_stack_trace(int level)
{
    std::vector<uint64_t> ret_addrs;
    get_ret_addrs_in_stack(ret_addrs, g_enclave_base, level);
    PRINTF("============= Stack Trace Begin ==============\n");
    size_t ret_addr_arr_size = ret_addrs.size();
    uint64_t ret_addr_arr[ret_addr_arr_size];
    std::copy(ret_addrs.begin(), ret_addrs.end(), ret_addr_arr);
    sgxsan_ocall_addr2line_ex(ret_addr_arr, ret_addr_arr_size);
    // for (size_t i = 0; i < ret_addrs.size(); i++)
    // {
    //     sgxsan_ocall_addr2line(ret_addrs[i] - 1, (int)i);
    // }
    PRINTF("============== Stack Trace End ===============\n");
}

// ignore return address of current call
uint64_t get_last_return_address(uint64_t base_addr, int level)
{
    level += 1;
    uint64_t ret_addr = (uint64_t)__builtin_return_address(0);
    uint64_t bp = (uint64_t)__builtin_frame_address(0);
    for (int i = 0; i - level < 50; i++)
    {
        if (i >= level)
        {
            return ret_addr - base_addr;
        }
        bp = *(uint64_t *)bp;
        if (!is_addr_in_elrange(bp) || (bp == (uint64_t)get_tcs()))
            break;
        ret_addr = *(uint64_t *)(bp + 8);
        if (!is_addr_in_elrange(ret_addr))
            break;
    }
    return 0;
}