#include "ArgShadow.h"

__thread ArgShadowTy ArgShadowStack::arg_shadow_stack[MAX_STACK_DEPTH];
__thread size_t ArgShadowStack::stack_depth;

// C Wrappers
void PoisonArg(void *func_addr, int arg_pos) {
  ArgShadowStack::poison(func_addr, arg_pos);
}

bool ArgIsPoisoned(void *func_addr, int arg_pos) {
  return ArgShadowStack::query(func_addr, arg_pos);
}

void PushArgShadowStack(void *func_addr) { ArgShadowStack::push(func_addr); }

void PopArgShadowStack(void *func_addr) { ArgShadowStack::pop(func_addr); }

void ClearArgShadowStack() { ArgShadowStack::clear(); }
