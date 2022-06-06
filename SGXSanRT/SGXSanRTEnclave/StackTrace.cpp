#include "SGXSanLog.hpp"
#include "PoisonCheck.hpp"
#include "StackTrace.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SGXInternal.hpp"
#include <sgx_trts.h>
#include <cstdlib>

// level == 0 means return address of function that called 'get_ret_addrs_in_stack'
void get_ret_addrs_in_stack(std::vector<uint64_t> &ret_addrs, uint64_t enclave_base_addr, unsigned int level, size_t max_collect_count, uint64_t bp)
{
    if (bp == 0)
        bp = (uint64_t)__builtin_frame_address(0);
    uint64_t ret_addr = *(uint64_t *)(bp + 8);
    for (unsigned int i = 0; i < max_collect_count + level; i++)
    {
        if (i >= level)
        {
            ret_addrs.emplace_back(ret_addr - enclave_base_addr);
        }
        bp = *(uint64_t *)bp;
        if (not is_stack_addr((void *)bp, sizeof(uintptr_t)))
            break;
        ret_addr = *(uint64_t *)(bp + 8);
        if (!sgx_is_within_enclave((void *)ret_addr, 1))
            break;
    }
}

void sgxsan_print_stack_trace(log_level ll, unsigned int level, uint64_t bp, uint64_t ip)
{
#if (DUMP_STACK_TRACE)
    std::vector<uint64_t> ret_addrs;
    if (ip != 0)
        ret_addrs.push_back(ip - g_enclave_base);
    get_ret_addrs_in_stack(ret_addrs, g_enclave_base, level, 50, bp);
    sgxsan_log(ll, false, "============= Stack Trace Begin ==============\n");
    size_t ret_addr_arr_size = ret_addrs.size();
    uint64_t addr_arr[ret_addr_arr_size];
    for (size_t i = 0; i < ret_addr_arr_size; i++)
    {
        addr_arr[i] = ret_addrs[i] - 1;
    }
    sgxsan_ocall_addr2line_ex(addr_arr, ret_addr_arr_size);
    // for (size_t i = 0; i < ret_addrs.size(); i++)
    // {
    //     sgxsan_ocall_addr2line(ret_addrs[i] - 1, (int)i);
    // }
    sgxsan_log(ll, false, "============== Stack Trace End ===============\n");
#endif
}

// ignore return address of current call
uint64_t get_last_return_address(uint64_t enclave_base_addr, unsigned int level)
{
    std::vector<uint64_t> ret_addrs;
    get_ret_addrs_in_stack(ret_addrs, enclave_base_addr, level, 1);
    assert(ret_addrs.size() == 1);
    return ret_addrs[0];
}