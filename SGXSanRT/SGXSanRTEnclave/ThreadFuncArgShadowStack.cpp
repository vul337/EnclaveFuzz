#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <algorithm>
#include <stack>
#include "ThreadFuncArgShadowStack.hpp"
#include "SGXSanLog.hpp"

// function addr -> poisoned function argument map [-1,0,1,...,MAX_ARG_NUM-2] ( -1 means return value)
// too large will cost too much trts TLS init time (based on memset)
#define MAX_ARG_NUM 128 // must be multiple of 8
#define MAX_STACK_DEPTH 512
struct FuncArgShadowTy
{
    uint64_t func_addr;
    bool arg_shadow[MAX_ARG_NUM];
};

class ThreadFuncArgShadowStack
{
public:
    static void init();
    static void destroy();
    static void poison_arg(uint64_t func_addr, int64_t arg_pos);
    static void unpoison_arg(uint64_t func_addr, int64_t arg_pos);
    static bool query_arg(uint64_t func_addr, int64_t arg_pos);
    static bool onetime_query_arg(uint64_t func_addr, int64_t arg_pos);
    static void clear_frame(uint64_t func_addr);
    static void push_frame(uint64_t func_addr);
    static void pop_frame(uint64_t func_addr);
    static void show_arg_shadow(uint64_t func_addr);

private:
    static __thread FuncArgShadowTy thread_func_arg_shadow_stack[MAX_STACK_DEPTH];
    static __thread size_t thread_func_arg_shadow_stack_current_depth;
};
__thread FuncArgShadowTy ThreadFuncArgShadowStack::thread_func_arg_shadow_stack[MAX_STACK_DEPTH];
__thread size_t ThreadFuncArgShadowStack::thread_func_arg_shadow_stack_current_depth;

// a serial of c wrapper for instrumentation
void ThreadFuncArgShadowStack::init()
{
    assert(thread_func_arg_shadow_stack_current_depth == 0);
}

void ThreadFuncArgShadowStack::destroy()
{
    assert(thread_func_arg_shadow_stack_current_depth == 0);
}

void ThreadFuncArgShadowStack::poison_arg(uint64_t func_addr, int64_t arg_pos)
{
    assert(-1 <= arg_pos && arg_pos <= (MAX_ARG_NUM - 2));
    // There is no shadow stack frame for current function (stack_depth == 0 or top.func_addr != func_addr):
    // 1) the caller maybe uninstrumented since it's a third-party library's function (ret case)
    if (thread_func_arg_shadow_stack_current_depth == 0)
        return;
    auto &top = thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1];
    if (top.func_addr != func_addr)
        return;
    top.arg_shadow[arg_pos + 1] = true;
    // show_arg_shadow(func_addr);
}

void ThreadFuncArgShadowStack::unpoison_arg(uint64_t func_addr, int64_t arg_pos)
{
    assert(-1 <= arg_pos && arg_pos <= (MAX_ARG_NUM - 2));
    assert(thread_func_arg_shadow_stack_current_depth > 0);
    auto &top = thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1];
    assert(top.func_addr == func_addr);
    top.arg_shadow[arg_pos + 1] = false;
}

void ThreadFuncArgShadowStack::show_arg_shadow(uint64_t func_addr)
{
    auto &top = thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1];
    assert(top.func_addr == func_addr);
    log_trace("[ Argument Shadow of 0x%lx ]:", func_addr);
    for (auto shadow_item : top.arg_shadow)
    {
        log_trace(" %d", shadow_item);
    }
    log_trace(" \n");
}

bool ThreadFuncArgShadowStack::query_arg(uint64_t func_addr, int64_t arg_pos)
{
    assert(-1 <= arg_pos && arg_pos <= (MAX_ARG_NUM - 2));
    // There is no shadow stack frame for current function (stack_depth == 0 or top.func_addr != func_addr):
    // 1) the caller maybe uninstrumented since it's a third-party library's function (arg case)
    // 2) there is no inter-procedure shadow propagation at that caller-callee, but exists at other caller-callee pairs (arg case)
    if (thread_func_arg_shadow_stack_current_depth == 0)
        return false;
    auto &top = thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1];
    if (top.func_addr != func_addr)
        return false;
    // show_arg_shadow(func_addr);
    return top.arg_shadow[arg_pos + 1];
}

bool ThreadFuncArgShadowStack::onetime_query_arg(uint64_t func_addr, int64_t arg_pos)
{
    bool is_poisoned = query_arg(func_addr, arg_pos);
    unpoison_arg(func_addr, arg_pos);
    return is_poisoned;
}

void ThreadFuncArgShadowStack::clear_frame(uint64_t func_addr)
{
    sgxsan_error(thread_func_arg_shadow_stack_current_depth == 0 || thread_func_arg_shadow_stack_current_depth > MAX_STACK_DEPTH, "Break down thread_func_arg_shadow_stack");
    FuncArgShadowTy &top = thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1];
    assert(top.func_addr == func_addr);
    // clear arg_shadow
    uint64_t *p = (uint64_t *)top.arg_shadow;
    for (size_t step = 0; step < (MAX_ARG_NUM / 8); step++)
    {
        p[step] = 0;
    }
}

void ThreadFuncArgShadowStack::push_frame(uint64_t func_addr)
{
    thread_func_arg_shadow_stack_current_depth++;
    sgxsan_error(thread_func_arg_shadow_stack_current_depth > MAX_STACK_DEPTH, "Exceed ceiling of thread_func_arg_shadow_stack");
    auto &top = thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1];
    top.func_addr = func_addr;
    // clear arg_shadow
    uint64_t *p = (uint64_t *)top.arg_shadow;
    for (size_t step = 0; step < (MAX_ARG_NUM / 8); step++)
    {
        p[step] = 0;
    }
}

void ThreadFuncArgShadowStack::pop_frame(uint64_t func_addr)
{
    sgxsan_error(thread_func_arg_shadow_stack_current_depth == 0, "Under bottom of thread_func_arg_shadow_stack");
    assert(thread_func_arg_shadow_stack[thread_func_arg_shadow_stack_current_depth - 1].func_addr == func_addr);
    thread_func_arg_shadow_stack_current_depth--;
}

// c wrappers
void init_thread_func_arg_shadow_stack()
{
    ThreadFuncArgShadowStack::init();
}

void destroy_thread_func_arg_shadow_stack()
{
    ThreadFuncArgShadowStack::destroy();
}

void poison_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos)
{
    ThreadFuncArgShadowStack::poison_arg(func_addr, arg_pos);
}

void unpoison_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos)
{
    ThreadFuncArgShadowStack::unpoison_arg(func_addr, arg_pos);
}

bool query_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos)
{
    return ThreadFuncArgShadowStack::query_arg(func_addr, arg_pos);
}

bool onetime_query_thread_func_arg_shadow_stack(uint64_t func_addr, int64_t arg_pos)
{
    return ThreadFuncArgShadowStack::onetime_query_arg(func_addr, arg_pos);
}

void clear_thread_func_arg_shadow_stack(uint64_t func_addr)
{
    ThreadFuncArgShadowStack::clear_frame(func_addr);
}

void push_thread_func_arg_shadow_stack(uint64_t func_addr)
{
    ThreadFuncArgShadowStack::push_frame(func_addr);
}

void pop_thread_func_arg_shadow_stack(uint64_t func_addr)
{
    ThreadFuncArgShadowStack::pop_frame(func_addr);
}