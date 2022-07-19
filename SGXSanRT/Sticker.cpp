#include "Poison.h"
#include "SGXSanRT.h"
#include "arch.h"
#include "cpuid.h"
#include "sgx_edger8r.h"
#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_thread.h"
#include "sgx_urts.h"
#include "trts_internal.h"
#include <algorithm>
#include <errno.h>
#include <map>
#include <pthread.h>
#include <stack>
#include <thread_data.h>
#include <unistd.h>
#include <vector>

/// Global Data

/*SECS data structure*/
typedef struct _global_data_sim_t {
  secs_t *secs_ptr;
  sgx_cpu_svn_t cpusvn_sim;
  uint64_t seed; /* to initialize the PRNG */
} global_data_sim_t;

extern global_data_sim_t g_global_data_sim;
secs_t g_secs;

/// TCS Manager

TrustThreadPool _g_thread_pool;
TrustThreadPool *g_thread_pool = &_g_thread_pool;

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

static void SGXInitInternal() {
  g_global_data_sim.secs_ptr = &g_secs;
  PoisonShadow((uptr)&g_secs, sizeof(g_secs), kAsanNotPoisonedMagic);
}

__thread sgx_ocall_table_t *g_enclave_ocall_table = nullptr;
__thread bool RunInEnclave = false;
__thread bool FirstECall = true;
__thread TrustThread *sgxsan_thread = nullptr;

/// Thread Data
extern "C" thread_data_t *get_thread_data() { return &sgxsan_thread->m_td; }

extern "C" sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index,
                                  const void *ocall_table, void *ms) {
  (void)eid;
  RunInEnclave = true;
  bool curIsFirstECall = false;
  if (FirstECall) {
    FirstECall = false;
    curIsFirstECall = true;
    sgxsan_thread = g_thread_pool->alloc(gettid());
  }
  sgxsan_assert(index < (int)g_ecall_table.nr_ecall);
  g_enclave_ocall_table = (sgx_ocall_table_t *)ocall_table;
  get_thread_data()->last_error = errno;
  auto result = ((ecall_func_t)g_ecall_table.ecall_table[index].ecall_addr)(ms);
  if (curIsFirstECall) {
    g_thread_pool->free(sgxsan_thread);
    sgxsan_thread = nullptr;
    FirstECall = true;
  }
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

sgx_status_t sgx_cpuidex(int cpuinfo[4], int leaf, int subleaf) {
  if (cpuinfo == NULL)
    return SGX_ERROR_INVALID_PARAMETER;

  __cpuidex(cpuinfo, leaf, subleaf);
  return SGX_SUCCESS;
}

sgx_status_t sgx_cpuid(int cpuinfo[4], int leaf) {
  return sgx_cpuidex(cpuinfo, leaf, 0);
}
}

/// life time management
sgx_status_t SGXAPI sgx_create_enclave(const char *file_name, const int debug,
                                       sgx_launch_token_t *launch_token,
                                       int *launch_token_updated,
                                       sgx_enclave_id_t *enclave_id,
                                       sgx_misc_attribute_t *misc_attr) {
  RunInEnclave = true;
  SGXInitInternal();
  RunInEnclave = false;
  return SGX_SUCCESS;
}

extern "C" sgx_status_t sgx_create_enclave_ex(
    const char *file_name, const int debug, sgx_launch_token_t *launch_token,
    int *launch_token_updated, sgx_enclave_id_t *enclave_id,
    sgx_misc_attribute_t *misc_attr, const uint32_t ex_features,
    const void *ex_features_p[32]) {
  RunInEnclave = true;
  SGXInitInternal();
  RunInEnclave = false;
  return SGX_SUCCESS;
}

sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
  return SGX_SUCCESS;
}
