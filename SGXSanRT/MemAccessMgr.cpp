#include "MemAccessMgr.h"

thread_local std::deque<FetchInfo> MemAccessMgr::m_control_fetchs;
__thread bool MemAccessMgr::m_active;
__thread bool MemAccessMgr::m_inited;
__thread size_t MemAccessMgr::m_out_enclave_access_cnt;
__thread size_t MemAccessMgr::m_in_enclave_access_cnt;

// C Wrappers
void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return; // leave it to guard page check
  if (not is_write) {
    auto res =
        MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp, parent_func);
    if (res) {
      sgxsan_warning(
          true,
          "Detect Double-Fetch Situation, and modify it with random data\n");
      size_t step_times = size / sizeof(int), remained = size % sizeof(int);
      int *ptr_i32 = (int *)ptr;
      for (size_t step = 0; step < step_times; step++) {
        ptr_i32[step] = rand();
      }
      uint8_t *ptr_remained = (uint8_t *)((uptr)ptr + size * sizeof(int));
      if (remained > 0) {
        int rand_res = rand();
        for (size_t i = 0; i < remained; i++) {
          ptr_remained[i] = rand_res >> (i * 8);
        }
      }
    }
  }
  MemAccessMgr::add_out_of_enclave_access_cnt();
}

void MemAccessMgrActive() { MemAccessMgr::active(); }

void MemAccessMgrDeactive() { MemAccessMgr::deactive(); }

void MemAccessMgrInEnclaveAccess() {
  MemAccessMgr::add_in_enclave_access_cnt();
}
