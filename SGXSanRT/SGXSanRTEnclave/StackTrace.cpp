#include "SGXSanLog.hpp"
#include "PoisonCheck.hpp"
#include "StackTrace.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SGXInternal.hpp"
#define UNW_LOCAL_ONLY
#include "libunwind_i.h"
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

void sgxsan_print_stack_trace(log_level ll)
{
#if (DUMP_STACK_TRACE)
    std::vector<uint64_t> ret_addrs;
    libunwind_backtrace(ret_addrs, g_enclave_base);
    size_t ret_addr_arr_size = ret_addrs.size();
    if (ret_addr_arr_size > 0)
    {
        sgxsan_log(ll, false, "============= Stack Trace Begin ==============\n");
        uint64_t addr_arr[ret_addr_arr_size];
        for (size_t i = 0; i < ret_addr_arr_size; i++)
            addr_arr[i] = ret_addrs[i] - 1;
        sgxsan_ocall_addr2line(addr_arr, ret_addr_arr_size);
        sgxsan_log(ll, false, "============== Stack Trace End ===============\n");
    }
#else
    (void)ll;
#endif
}

// ignore return address of current call
uint64_t get_last_return_address(uint64_t enclave_base_addr, unsigned int level)
{
    std::vector<uint64_t> ret_addrs;
    libunwind_backtrace(ret_addrs, enclave_base_addr, level + 2);
    assert(ret_addrs.size() == level + 2);
    return ret_addrs[level + 1];
}

// https://eli.thegreenplace.net/2015/programmatic-access-to-the-call-stack-in-c/
void libunwind_backtrace(std::vector<uint64_t> &ret_addrs, uint64_t base_addr, size_t max_collect_count)
{
    unw_context_t context;
    if (unw_getcontext(&context) != 0)
        return;

    // Initialize cursor to current frame for local unwinding.
    unw_cursor_t cursor;
    if (unw_init_local(&cursor, &context) != 0)
        return;

    // check before unw_step to avoid sgxsdk's abort (sdk/cpprt/linux/libunwind/src/x86_64/Ginit.c:139)
    sgxsan_error(not sgx_is_within_enclave((const void *)((struct cursor *)&cursor)->dwarf.ip, 4096), "Fail to get first stack frame\n");

    // Unwind frames one by one, going up the frame stack.
    unw_word_t pc;
    while (unw_step(&cursor) > 0)
    {
        unw_get_reg(&cursor, UNW_REG_IP, &pc);
        if (pc == 0 or not sgx_is_within_enclave((const void *)pc, 1))
            break;
        ret_addrs.push_back(pc - base_addr);
        if (max_collect_count && ret_addrs.size() >= max_collect_count)
            break;
        // check before unw_step to avoid sgxsdk's abort
        if (not sgx_is_within_enclave((const void *)((struct cursor *)&cursor)->dwarf.ip, 4096))
            break;
    }
}