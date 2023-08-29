#include "MemAccessMgr.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanRTCom.h"
#include <deque>
#include <sgx_trts.h>
#include <string.h>

#define FUNC_NAME_MAX_LEN 127
#define CONTROL_FETCH_QUEUE_MAX_SIZE 3
struct FetchInfo {
  const void *start_addr = nullptr;
  size_t size = 0;
  char parent_func[FUNC_NAME_MAX_LEN + 1] = {'\0'};
  bool used_to_cmp = false;
};

extern "C" __attribute__((weak)) bool DFCmpFuncNameInTOCTOU();

class MemAccessMgr {
public:
  // add at TBridge
  static void init() {
    m_inited = true;
    m_active = false;
    m_control_fetchs = new std::deque<FetchInfo>();
    m_out_of_enclave_access_cnt = 0;
    m_in_enclave_access_cnt = 0;
  }

  static void destroy() {
    log_trace("[Access Count (Out/In)] %lld/%lld\n",
              m_out_of_enclave_access_cnt, m_in_enclave_access_cnt);
    m_out_of_enclave_access_cnt = 0;
    m_in_enclave_access_cnt = 0;
    delete m_control_fetchs;
    m_control_fetchs = nullptr;
    m_active = false;
    m_inited = false;
  }

  static void active() { m_active = true; }

  static void deactive() { m_active = false; }

  static void add_out_of_enclave_access_cnt() {
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
    if (m_active) {
      sgxsan_assert(m_inited);
      m_out_of_enclave_access_cnt++;
    }
#endif
  }

  static void add_in_enclave_access_cnt() {
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
    if (m_active) {
      sgxsan_assert(m_inited);
      m_in_enclave_access_cnt++;
    }
#endif
  }

  static bool double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp, char *parent_func) {
    sgxsan_assert(ptr && size > 0 && sgx_is_outside_enclave(ptr, size));
    // there may be ocall and ocall return before enter first ecall
    // When before ECall, OCall is called and return, m_active will set to true
    // but m_inited is still false
    if (!m_active or !m_inited)
      return false;
    sgxsan_assert(m_control_fetchs);
    if (used_to_cmp) {
      // it's a fetch used to compare, maybe used to 'check'
      while (m_control_fetchs->size() >= CONTROL_FETCH_QUEUE_MAX_SIZE) {
        m_control_fetchs->pop_front();
      }
      FetchInfo info;
      info.start_addr = ptr;
      info.size = size;
      info.used_to_cmp = used_to_cmp;
      strncpy(info.parent_func, parent_func,
              std::min((size_t)FUNC_NAME_MAX_LEN, strlen(parent_func)));
      info.parent_func[FUNC_NAME_MAX_LEN] = 0;
      m_control_fetchs->push_back(info);
      return false;
    } else {
      bool result = false;
      // it's a non-compared fetch, maybe used to 'use'
      for (auto &control_fetch : *m_control_fetchs) {
        // if parent function name is not known, assume at same function and
        // only check overlap
        bool at_same_func = true;
        if (DFCmpFuncNameInTOCTOU and DFCmpFuncNameInTOCTOU()) {
          if (parent_func) {
            at_same_func = strncmp(control_fetch.parent_func, parent_func,
                                   std::min((size_t)FUNC_NAME_MAX_LEN,
                                            strlen(parent_func))) == 0;
          }
        }
        bool is_overlap =
            RangesOverlap((const char *)control_fetch.start_addr,
                          control_fetch.size, (const char *)ptr, size);
        if (at_same_func && is_overlap) {
          result = true;
          break;
        }
      }
      return result;
    }
  }

private:
  static __thread bool m_inited;
  static __thread bool m_active;
  static __thread std::deque<FetchInfo> *m_control_fetchs;
  static __thread size_t m_out_of_enclave_access_cnt;
  static __thread size_t m_in_enclave_access_cnt;
};

__thread bool MemAccessMgr::m_inited;
__thread bool MemAccessMgr::m_active;
__thread std::deque<FetchInfo> *MemAccessMgr::m_control_fetchs;
__thread size_t MemAccessMgr::m_out_of_enclave_access_cnt;
__thread size_t MemAccessMgr::m_in_enclave_access_cnt;

// a list of c wrapper of MemAccessMgr that exported for use
void MemAccessMgrInit() { MemAccessMgr::init(); }

void MemAccessMgrDestroy() { MemAccessMgr::destroy(); }

void MemAccessMgrActive() { MemAccessMgr::active(); }

void MemAccessMgrDeactive() { MemAccessMgr::deactive(); }

void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return;
  if (not is_write) {
    bool res =
        MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp, parent_func);
    sgxsan_warning(res, "Detect Double-Fetch Situation\n");
  }
  MemAccessMgr::add_out_of_enclave_access_cnt();
}

void MemAccessMgrInEnclaveAccess() {
  MemAccessMgr::add_in_enclave_access_cnt();
}
