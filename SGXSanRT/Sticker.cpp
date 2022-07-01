#include "SGXSanRT.h"
#include "sgx_edger8r.h"
#include <errno.h>
#include <pthread.h>
#include <stack>
#include <vector>

/// Thread Data
typedef size_t sys_word_t;

typedef struct _thread_data_t {
  sys_word_t self_addr;
  sys_word_t last_sp;          /* set by urts, relative to TCS */
  sys_word_t stack_base_addr;  /* set by urts, relative to TCS */
  sys_word_t stack_limit_addr; /* set by urts, relative to TCS */
  sys_word_t first_ssa_gpr;    /* set by urts, relative to TCS */
  sys_word_t
      stack_guard; /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

  sys_word_t flags;
  sys_word_t xsave_size; /* in bytes (se_ptrace.c needs to know its offset).*/
  sys_word_t last_error; /* init to be 0. Used by trts. */
  struct _thread_data_t *m_next;
  sys_word_t tls_addr;  /* points to TLS pages */
  sys_word_t tls_array; /* points to TD.tls_addr relative to TCS */
  intptr_t exception_flag;
  sys_word_t cxx_thread_info[6];
  sys_word_t stack_commit_addr;
} thread_data_t;

__thread thread_data_t td;

extern "C" thread_data_t *get_thread_data() { return &td; }

/// Birdge Sticker
typedef struct {
  const void *ecall_addr;
  uint8_t is_priv;
  uint8_t is_switchless;
} ecall_addr_t;

typedef struct {
  size_t nr_ecall;
  ecall_addr_t ecall_table[1];
} ecall_table_t;

typedef struct _ocall_table_t {
  size_t count;
  void *ocall[];
} sgx_ocall_table_t;

typedef sgx_status_t (*ecall_func_t)(void *ms);
typedef sgx_status_t (*bridge_fn_t)(const void *);
extern const ecall_table_t g_ecall_table;

__thread sgx_ocall_table_t *g_enclave_ocall_table;
__thread bool RunInEnclave;
extern "C" sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index,
                                  const void *ocall_table, void *ms) {
  (void)eid;
  sgxsan_assert(index < (int)g_ecall_table.nr_ecall);
  g_enclave_ocall_table = (sgx_ocall_table_t *)ocall_table;
  RunInEnclave = true;
  td.last_error = errno;
  auto result = ((ecall_func_t)g_ecall_table.ecall_table[index].ecall_addr)(ms);
  RunInEnclave = false;
  return result;
}
extern "C" sgx_status_t sgx_ecall_switchless(const sgx_enclave_id_t eid,
                                             const int index,
                                             const void *ocall_table, void *ms)
    __attribute__((alias("sgx_ecall")));

extern "C" sgx_status_t sgx_ocall(const unsigned int index, void *ms) {
  RunInEnclave = false;
  sgxsan_assert(index < g_enclave_ocall_table->count);
  auto result = ((bridge_fn_t)g_enclave_ocall_table->ocall[index])(ms);
  RunInEnclave = true;
  return result;
}
extern "C" sgx_status_t sgx_ocall_switchless(const unsigned int index, void *ms)
    __attribute__((alias("sgx_ocall")));

// OCAllocStack
thread_local std::stack<std::vector<void *>> OCAllocStack;

extern "C" void PushOCAllocStack() {
  OCAllocStack.emplace(std::vector<void *>{});
}
extern "C" void PopOCAllocStack() { OCAllocStack.pop(); }

extern "C" void *sgx_ocalloc(size_t size) {
  auto &top = OCAllocStack.top();
  void *ocallocAddr = REAL(malloc)(size);
  top.push_back(ocallocAddr);
  return ocallocAddr;
}

extern "C" void sgx_ocfree() {
  auto &top = OCAllocStack.top();
  for (auto ocallocAddr : top) {
    REAL(free)(ocallocAddr);
  }
}

// replace libsgx_tstdc with normal glibc and additional API
extern "C" {

int *__errno(void) { return &errno; }

void *__memset(void *dst, int c, size_t n) { return memset(dst, c, n); }

int memset_s(void *s, size_t smax, int c, size_t n) {
  auto dst = memset(s, c, std::min(smax, n));
  return dst == s ? 0 : errno;
}

int heap_init(void *_heap_base, size_t _heap_size, size_t _heap_min_size,
              int _is_edmm_supported) {
  return SGX_SUCCESS;
}

int rsrv_mem_init(void *_rsrv_mem_base, size_t _rsrv_mem_size,
                  size_t _rsrv_mem_min_size) {
  return SGX_SUCCESS;
}

int sgx_init_string_lib(uint64_t cpu_feature_indicator) {
  (void)cpu_feature_indicator;
  return 0;
}

void *alloca(size_t __size) { return __builtin_alloca(__size); }

sgx_status_t SGXAPI sgx_cpuid(int cpuinfo[4], int leaf) { return SGX_SUCCESS; }
}