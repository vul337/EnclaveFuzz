#pragma once

#define NOINLINE __attribute__((noinline))
#define INTERFACE_ATTRIBUTE __attribute__((visibility("default")))

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#ifndef GET_CALLER_PC_BP_SP
#define GET_CALLER_PC_BP_SP                                                    \
  uptr bp = (uptr)__builtin_frame_address(0);                                  \
  uptr pc = (uptr)__builtin_return_address(0);                                 \
  uptr local_stack;                                                            \
  uptr sp = (uptr)&local_stack
#endif
