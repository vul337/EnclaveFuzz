#include "EncalveTLSLifetime.hpp"
#include "MemAccessMgr.hpp"
#include "SGXSanRTCom.h"
#include "ThreadFuncArgShadowStack.hpp"

__thread int64_t TLS_init_count;

void TDECallConstructor() {
  if (TLS_init_count == 0) {
    // root ecall
    MemAccessMgrInit();
    init_thread_func_arg_shadow_stack();
  }
  TLS_init_count++;
  sgxsan_assert(TLS_init_count < 1024);
}

void TDECallDestructor() {
  if (TLS_init_count == 1) {
    // root ecall
    MemAccessMgrDestroy();
    destroy_thread_func_arg_shadow_stack();
  }
  TLS_init_count--;
  sgxsan_assert(TLS_init_count >= 0);
}