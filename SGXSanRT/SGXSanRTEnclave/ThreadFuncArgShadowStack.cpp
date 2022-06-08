#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <stack>
#include "ThreadFuncArgShadowStack.hpp"
#include "SGXSanLog.hpp"

// function addr -> poisoned function argument index set
// ( -1 means return value)
struct FuncArgShadowTy
{
    uint64_t func_addr;
    std::unordered_set<int64_t> arg_shadow;
    FuncArgShadowTy(uint64_t &_func_addr, std::unordered_set<int64_t> &_arg_shadow)
    {
        func_addr = _func_addr;
        arg_shadow = _arg_shadow;
    }
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
    static __thread std::stack<FuncArgShadowTy> *thread_func_arg_shadow_stack;
};
__thread std::stack<FuncArgShadowTy> *ThreadFuncArgShadowStack::thread_func_arg_shadow_stack;

// a serial of c wrapper for instrumentation
void ThreadFuncArgShadowStack::init()
{
    thread_func_arg_shadow_stack = new std::stack<FuncArgShadowTy>();
}

void ThreadFuncArgShadowStack::destroy()
{
    delete thread_func_arg_shadow_stack;
    thread_func_arg_shadow_stack = nullptr;
}

void ThreadFuncArgShadowStack::poison_arg(uint64_t func_addr, int64_t arg_pos)
{
    uint64_t stack_size = thread_func_arg_shadow_stack->size();

    if (stack_size == 0 ||
        thread_func_arg_shadow_stack->top().func_addr != func_addr)
    {
        // the caller maybe uninstrumented since it's a third-party library's function
        // so there is no shadow stack frame for current function
        return;
    }
    FuncArgShadowTy &correct_top = thread_func_arg_shadow_stack->top();
    assert(correct_top.func_addr == func_addr);
    correct_top.arg_shadow.emplace(arg_pos);
    // show_arg_shadow(func_addr);
}

void ThreadFuncArgShadowStack::unpoison_arg(uint64_t func_addr, int64_t arg_pos)
{
    uint64_t stack_size = thread_func_arg_shadow_stack->size();
    assert(stack_size > 0);
    FuncArgShadowTy &top = thread_func_arg_shadow_stack->top();
    assert(top.func_addr == func_addr);
    top.arg_shadow.erase(arg_pos);
}

void ThreadFuncArgShadowStack::show_arg_shadow(uint64_t func_addr)
{
    FuncArgShadowTy &top = thread_func_arg_shadow_stack->top();
    assert(top.func_addr == func_addr);
    std::unordered_set<int64_t> &arg_shadow = top.arg_shadow;
    log_trace("[ Argument Shadow of 0x%lx ]:", func_addr);
    for (int64_t shadow_item : arg_shadow)
    {
        log_trace(" %ld", shadow_item);
    }
    log_trace(" \n");
}

bool ThreadFuncArgShadowStack::query_arg(uint64_t func_addr, int64_t arg_pos)
{
    uint64_t stack_size = thread_func_arg_shadow_stack->size();

    if (stack_size == 0 ||
        thread_func_arg_shadow_stack->top().func_addr != func_addr)
    {
        // the caller maybe uninstrumented since it's a third-party library's function,
        // or there is no inter-procedure shadow propagation at that caller-callee, but exists at other caller-callee pairs
        // then there is no shadow stack frame for current function
        return false;
    }
    FuncArgShadowTy &correct_top = thread_func_arg_shadow_stack->top();
    assert(correct_top.func_addr == func_addr);
    // show_arg_shadow(func_addr);
    return correct_top.arg_shadow.count(arg_pos) != 0;
}

bool ThreadFuncArgShadowStack::onetime_query_arg(uint64_t func_addr, int64_t arg_pos)
{
    bool is_poisoned = query_arg(func_addr, arg_pos);
    unpoison_arg(func_addr, arg_pos);
    return is_poisoned;
}

void ThreadFuncArgShadowStack::clear_frame(uint64_t func_addr)
{
    uint64_t stack_size = thread_func_arg_shadow_stack->size();
    assert(stack_size > 0);
    FuncArgShadowTy &top = thread_func_arg_shadow_stack->top();
    assert(top.func_addr == func_addr);
    top.arg_shadow.clear();
}

void ThreadFuncArgShadowStack::push_frame(uint64_t func_addr)
{
    std::unordered_set<int64_t> new_arg_shadow;
    new_arg_shadow.clear();
    thread_func_arg_shadow_stack->emplace(func_addr, new_arg_shadow);
}

void ThreadFuncArgShadowStack::pop_frame(uint64_t func_addr)
{
    uint64_t stack_size = thread_func_arg_shadow_stack->size();
    assert(stack_size > 0);
    FuncArgShadowTy &top = thread_func_arg_shadow_stack->top();
    assert(top.func_addr == func_addr);
    thread_func_arg_shadow_stack->pop();
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