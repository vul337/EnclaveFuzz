#pragma once

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
void init_thread_func_arg_shadow_stack();
void destroy_thread_func_arg_shadow_stack();

void poison_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos);
void unpoison_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos);
bool onetime_query_thread_func_arg_shadow_stack(uint64_t func_addr,
                                                int64_t arg_pos);
bool query_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos);
void clear_thread_func_arg_shadow_stack(int64_t arg_pos);

void push_thread_func_arg_shadow_stack(uint64_t func_addr);
void pop_thread_func_arg_shadow_stack(uint64_t func_addr);
#if defined(__cplusplus)
}
#endif