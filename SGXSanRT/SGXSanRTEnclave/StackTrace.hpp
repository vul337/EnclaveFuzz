#pragma once
#include <vector>
#include <stdint.h>
void get_ret_addrs_in_stack(std::vector<int> &ret_addrs, uint64_t base_addr = 0, int level = 0);