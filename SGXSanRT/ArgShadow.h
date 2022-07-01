#pragma once

#include "SGXSanRT.h"

// Function address -> function arguments' shadow map
// [-1,0,1,...,MAX_ARG_NUM-2] ( -1 means return value)
#define MAX_ARG_NUM 512 // must be multiple of 8
#define MAX_STACK_DEPTH 1028

struct ArgShadowTy {
  void *func_addr;
  bool arg_shadows[MAX_ARG_NUM];
};

class ArgShadowStack {
public:
  static void poison(void *func_addr, int arg_pos) {
    sgxsan_assert(-1 <= arg_pos && arg_pos <= (MAX_ARG_NUM - 2));
    /* There is no shadow stack frame for current function
     * (i.e. stack_depth == 0 or top.func_addr != func_addr):
     * 1) caller maybe uninstrumented since it's a 3rd-party function (ret case)
     */
    if (stack_depth == 0)
      return;
    auto &top = arg_shadow_stack[stack_depth - 1];
    if (top.func_addr != func_addr)
      return;
    top.arg_shadows[arg_pos + 1] = true;
    // show_arg_shadow(func_addr);
  }

  static bool query(void *func_addr, int arg_pos) {
    sgxsan_assert(-1 <= arg_pos && arg_pos <= (MAX_ARG_NUM - 2));
    /* There may be no shadow stack frame for current function
     * (i.e. stack_depth == 0 or top.func_addr != func_addr):
     * 1) caller maybe uninstrumented since it's a 3rd-party function (arg case)
     * 2) there is no cross-function shadow propagation at that callee, but
     * exists when called from other callers (arg case) */
    if (stack_depth == 0)
      return false;
    auto &top = arg_shadow_stack[stack_depth - 1];
    if (top.func_addr != func_addr)
      return false;
    return top.arg_shadows[arg_pos + 1];
  }

  static void push(void *func_addr) {
    stack_depth++;
    sgxsan_assert(1 <= stack_depth and stack_depth <= MAX_STACK_DEPTH);
    auto &top = arg_shadow_stack[stack_depth - 1];
    top.func_addr = func_addr;
    // clear arg_shadows
    uptr *p = (uptr *)top.arg_shadows;
    for (size_t step = 0; step < (MAX_ARG_NUM / sizeof(uptr)); step++) {
      p[step] = 0;
    }
  }

  static void pop(void *func_addr) {
    sgxsan_assert(stack_depth > 0 and
                  arg_shadow_stack[stack_depth - 1].func_addr == func_addr);
    stack_depth--;
  }

  static void show_arg_shadow(void *func_addr) {
    sgxsan_assert(stack_depth > 0);
    auto &top = arg_shadow_stack[stack_depth - 1];
    sgxsan_assert(top.func_addr == func_addr);
    log_trace("[ Argument Shadow of 0x%p ]:", func_addr);
    for (auto arg_shadow : top.arg_shadows) {
      log_trace(" %d", arg_shadow);
    }
    log_trace("\n");
  }

  static void init() { sgxsan_assert(0 == stack_depth); }
  static void destroy() { sgxsan_assert(0 == stack_depth); }

private:
  static __thread ArgShadowTy arg_shadow_stack[MAX_STACK_DEPTH];
  static __thread size_t stack_depth;
};

// Callback of SLSan
#if defined(__cplusplus)
extern "C" {
#endif
void PoisonArg(void *func_addr, int arg_pos);
bool ArgIsPoisoned(void *func_addr, int arg_pos);
void PushArgShadowStack(void *func_addr);
void PopArgShadowStack(void *func_addr);
#if defined(__cplusplus)
}
#endif