#pragma once

#include <stdint.h>
#include <vector>

void get_ret_addrs_in_stack(std::vector<uint64_t> &ret_addrs,
                            uint64_t enclave_base_addr = 0,
                            unsigned int level = 0,
                            size_t max_collect_count = 50, uint64_t bp = 0);
uint64_t get_last_return_address(uint64_t enclave_base_addr = 0,
                                 unsigned int level = 0);
void libunwind_backtrace(std::vector<uint64_t> &ret_addrs, uint64_t base_addr,
                         size_t max_collect_count = 0);