#pragma once

#include <vector>
#include <stdint.h>

void get_ret_addrs_in_stack(std::vector<uint64_t> &ret_addrs, uint64_t base_addr = 0, int level = 0);

uint64_t get_last_return_address(uint64_t base_addr, int level);