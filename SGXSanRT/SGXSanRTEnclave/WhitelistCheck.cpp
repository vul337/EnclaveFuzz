#include "WhitelistCheck.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanLog.hpp"
#include "StackTrace.hpp"
#include <deque>
#include <mbusafecrt.h>
#include <sgx_trts.h>
#include <string>

#define FUNC_NAME_MAX_LEN 127
#define CONTROL_FETCH_QUEUE_MAX_SIZE 3
struct FetchInfo {
  const void *start_addr = nullptr;
  size_t size = 0;
  char parent_func[FUNC_NAME_MAX_LEN + 1] = {'\0'};
  bool used_to_cmp = false;
};

// Init/Destroy at Enclave Tbridge Side, I didn't want to modify sgxsdk
// Active/Deactive at Enclave Tbridge Side to avoid nested calls, these
// operations are as close to Customized Enclave Side as possible Add at Enclave
// Tbridge Side to collect whitlist info Query at Customized Enclave Side for
// whitelist checking Global Proagate at Customized Enclave Side, which only
// consider global variables at Customized Enclave Side. This operation will use
// Add/Query
class WhitelistOfAddrOutEnclave {
public:
  // add at bridge
  static void init();
  static void destroy();
  static void iter(bool is_global = false);
  static void add(const void *ptr, size_t size);
  static bool add_global(const void *ptr, size_t size);
  static std::tuple<const void *, size_t, bool /* is_at_global? */>
  query(const void *ptr, size_t size);
  static std::pair<const void *, size_t> query_global(const void *ptr,
                                                      size_t size);
  static void global_propagate(const void *ptr);
  static void active();
  static void deactive();
  static bool double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp, char *parent_func);
  static void add_in_enclave_access_cnt() {
    if (m_whitelist_active) {
      sgxsan_assert(m_whitelist);
      m_in_enclave_access_cnt++;
    }
  }

private:
  static __thread std::map<const void *, size_t> *m_whitelist;
  // used in nested ecall-ocall case
  static __thread bool m_whitelist_active;
  static __thread std::deque<FetchInfo> *m_control_fetchs;
  static __thread size_t m_out_of_enclave_access_cnt;
  static __thread size_t m_in_enclave_access_cnt;
  static std::map<const void *, size_t> m_global_whitelist;
  static pthread_rwlock_t m_rwlock_global_whitelist;
};

__thread std::map<const void *, size_t> *WhitelistOfAddrOutEnclave::m_whitelist;
__thread bool WhitelistOfAddrOutEnclave::m_whitelist_active;
__thread std::deque<FetchInfo> *WhitelistOfAddrOutEnclave::m_control_fetchs;
__thread size_t WhitelistOfAddrOutEnclave::m_out_of_enclave_access_cnt;
__thread size_t WhitelistOfAddrOutEnclave::m_in_enclave_access_cnt;
std::map<const void *, size_t> WhitelistOfAddrOutEnclave::m_global_whitelist;
pthread_rwlock_t WhitelistOfAddrOutEnclave::m_rwlock_global_whitelist =
    PTHREAD_RWLOCK_INITIALIZER;

// add at bridge
void WhitelistOfAddrOutEnclave::init() {
  m_whitelist = new std::map<const void *, size_t>();
  m_whitelist_active = false;
  m_control_fetchs = new std::deque<FetchInfo>();
  m_out_of_enclave_access_cnt = 0;
  m_in_enclave_access_cnt = 0;
}

void WhitelistOfAddrOutEnclave::destroy() {
  delete m_whitelist;
  m_whitelist = nullptr;
  delete m_control_fetchs;
  m_control_fetchs = nullptr;
  m_whitelist_active = false;
  log_trace("[Access Count (Out/In)] %lld/%lld\n", m_out_of_enclave_access_cnt,
            m_in_enclave_access_cnt);
  m_out_of_enclave_access_cnt = 0;
  m_in_enclave_access_cnt = 0;
}

void WhitelistOfAddrOutEnclave::iter(bool is_global) {
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
  std::map<const void *, size_t> *whitelist =
      is_global ? &m_global_whitelist : m_whitelist;
  log_trace("[Whitelist] [%s(0x%p)] ", is_global ? "Global" : "Thread",
            whitelist);
  for (auto &item : *whitelist) {
    log_trace("0x%p(0x%llx) ", item.first, item.second);
  }
  log_trace(" %s", "\n");
#else
  (void)is_global;
#endif
}

std::pair<const void *, size_t> merge_adjacent_memory(const void *addr1,
                                                      size_t len1,
                                                      const void *addr2,
                                                      size_t len2) {
  sgxsan_assert(addr1 && addr2 && len1 > 0 && len2 > 0);
  const void *result_addr = nullptr;
  size_t result_len = 0;
  if ((uptr)addr1 <= (uptr)addr2 && (uptr)addr2 + len2 <= (uptr)addr1 + len1) {
    result_addr = addr1;
    result_len = len1;
  } else if ((uptr)addr2 < (uptr)addr1 &&
             (uptr)addr1 + len1 < (uptr)addr2 + len2) {
    result_addr = addr2;
    result_len = len2;
  } else if ((uptr)addr1 <= (uptr)addr2 && (uptr)addr2 <= (uptr)addr1 + len1) {
    result_addr = addr1;
    result_len = (uptr)addr2 + len2 - (uptr)addr1;
  } else if ((uptr)addr2 <= (uptr)addr1 && (uptr)addr1 <= (uptr)addr2 + len2) {
    result_addr = addr2;
    result_len = (uptr)addr1 + len1 - (uptr)addr2;
  }
  return std::pair<const void *, size_t>(result_addr, result_len);
}

void WhitelistOfAddrOutEnclave::add(const void *ptr, size_t size) {
  // there may be ocall and ocall return before enter first ecall
  if (!m_whitelist)
    return;
  sgxsan_assert(ptr && size > 0 && !m_whitelist_active &&
                sgx_is_outside_enclave(ptr, size));
  iter();
  log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread", m_whitelist,
            "+", ptr, size);
  const void *target_addr = ptr;
  size_t target_len = size;
  bool hasMet = false;
  for (auto it = m_whitelist->begin(); it != m_whitelist->end();) {
    auto tmp =
        merge_adjacent_memory(target_addr, target_len, it->first, it->second);
    if (tmp.second != 0) {
      hasMet = true;
      log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread",
                m_whitelist, "-", it->first, it->second);
      it = m_whitelist->erase(it);
      target_addr = tmp.first;
      target_len = tmp.second;
    } else if (hasMet)
      break;
    else
      it++;
  }

  auto ret = m_whitelist->emplace(target_addr, target_len);
  iter();
  sgxsan_error(ret.second == false, "Insertion conflict?\n");
}

bool WhitelistOfAddrOutEnclave::add_global(const void *ptr, size_t size) {
  sgxsan_assert(ptr && size > 0 && sgx_is_outside_enclave(ptr, size));
  pthread_rwlock_wrlock(&m_rwlock_global_whitelist);
  iter(true);
  log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "+", ptr, size);
  const void *target_addr = ptr;
  size_t target_len = size;
  bool hasMet = false;
  for (auto it = m_global_whitelist.begin(); it != m_global_whitelist.end();) {
    auto tmp =
        merge_adjacent_memory(target_addr, target_len, it->first, it->second);
    if (tmp.second != 0) {
      hasMet = true;
      log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "-", it->first,
                it->second);
      it = m_global_whitelist.erase(it);
      target_addr = tmp.first;
      target_len = tmp.second;
    } else if (hasMet)
      break;
    else
      it++;
  }

  auto ret = m_global_whitelist.emplace(target_addr, target_len);
  iter(true);
  pthread_rwlock_unlock(&m_rwlock_global_whitelist);
  return ret.second;
}

// fetch must be a LoadInst
bool WhitelistOfAddrOutEnclave::double_fetch_detect(const void *ptr,
                                                    size_t size,
                                                    bool used_to_cmp,
                                                    char *parent_func) {
  sgxsan_assert(ptr && size > 0 && sgx_is_outside_enclave(ptr, size));
  // there may be ocall and ocall return before enter first ecall
  if (!m_whitelist_active)
    return false;
  sgxsan_assert(m_whitelist && m_control_fetchs);
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
      // if parent function name is not known, assume at same function and only
      // check overlap
      bool at_same_func = true;
      if (parent_func)
        at_same_func = strncmp(control_fetch.parent_func, parent_func,
                               std::min((size_t)FUNC_NAME_MAX_LEN,
                                        strlen(parent_func))) == 0;
      bool is_overlap =
          RangesOverlap((const char *)control_fetch.start_addr,
                        control_fetch.size, (const char *)ptr, size);
      result = result || (at_same_func && is_overlap);
    }
    return result;
  }
}

// return value:
// 1) query failed at thread and global whitelist
// 2) query success at thread whitelist (global whitelist may also contain this
// info) 3) query success at global whitelist (thread whitelist do not contain
// this info)
std::tuple<const void *, size_t, bool>
WhitelistOfAddrOutEnclave::query(const void *ptr, size_t size) {
  std::tuple<const void *, size_t, bool> ret,
      ignore_ret = std::tuple<const void *, size_t, bool>(nullptr, 1, false),
      false_ret = std::tuple<const void *, size_t, bool>(nullptr, 0, false);
  if (ptr == nullptr)
    return false_ret;
  sgxsan_assert(ptr && size > 0 && sgx_is_outside_enclave(ptr, size));
  // there may be ocall and ocall return before enter first ecall
  if (!m_whitelist_active)
    return ignore_ret;
  sgxsan_assert(m_whitelist);
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
  m_out_of_enclave_access_cnt++;
#endif
  log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread", m_whitelist,
            "?", ptr, size);

  iter();

  std::map<const void *, size_t>::iterator it;

  if (m_whitelist->size() == 0) {
    ret = false_ret;
    goto exit;
  }

  it = m_whitelist->lower_bound(ptr);

  if (LIKELY(it != m_whitelist->end() and it->first == ptr)) {
    ret = it->second < size ? false_ret
                            : std::tuple<const void *, size_t, bool>(
                                  it->first, it->second, false);
  } else if (it != m_whitelist->begin()) {
    // get the element just blow query addr
    --it;
    ret = (uptr)it->first + it->second < (uptr)ptr + size
              ? false_ret
              : std::tuple<const void *, size_t, bool>(it->first, it->second,
                                                       false);
  } else {
    // there is no <addr,size> pair can contain the query addr
    ret = false_ret;
  }
exit:
  if (ret == false_ret) {
    auto global_query_ret = query_global(ptr, size);
    ret = std::tuple<const void *, size_t, bool>(global_query_ret.first,
                                                 global_query_ret.second, true);
  }

  return ret;
}

std::pair<const void *, size_t>
WhitelistOfAddrOutEnclave::query_global(const void *ptr, size_t size) {
  pthread_rwlock_rdlock(&m_rwlock_global_whitelist);
  log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "?", ptr, size);
  iter(true);
  std::map<const void *, size_t>::iterator it;
  std::pair<const void *, size_t> ret,
      false_ret = std::pair<const void *, size_t>(nullptr, 0);

  if (m_global_whitelist.size() == 0) {
    ret = false_ret;
    goto exit;
  }

  it = m_global_whitelist.lower_bound(ptr);

  if (LIKELY(it != m_global_whitelist.end() and it->first == ptr)) {
    ret = it->second < size
              ? false_ret
              : std::pair<const void *, size_t>(it->first, it->second);
  } else if (it != m_global_whitelist.begin()) {
    // get the element just blow query addr
    --it;
    ret = (uptr)it->first + it->second < (uptr)ptr + size
              ? false_ret
              : std::pair<const void *, size_t>(it->first, it->second);
  } else {
    // there is no <addr,size> pair can contain the query addr
    ret = false_ret;
  }
exit:
  pthread_rwlock_unlock(&m_rwlock_global_whitelist);
  return ret;
}

// input ptr may be in Enclave or out of Enclave
void WhitelistOfAddrOutEnclave::global_propagate(const void *ptr) {
  if (sgx_is_within_enclave(ptr, 1))
    return;
  const void *find_start = nullptr;
  size_t find_size = 0;
  bool is_at_global = false;
  std::tie(find_start, find_size, is_at_global) = query(ptr, 1);
  if (is_at_global == false && find_size != 0 /* return case 2 */) {
    sgxsan_assert(sgx_is_outside_enclave(find_start, find_size));
    log_trace("[Whitelist] [Thread(0x%p)] => 0x%p => [Global]\n", m_whitelist,
              ptr);
    sgxsan_error(add_global(find_start, find_size) == false,
                 "Fail to propagate to global whitelist\n");
  }
}

void WhitelistOfAddrOutEnclave::active() { m_whitelist_active = true; }

void WhitelistOfAddrOutEnclave::deactive() { m_whitelist_active = false; }

// a list of c wrapper of WhitelistOfAddrOutEnclave that exported for use, class
// member function is inlined defaultly
void WhitelistOfAddrOutEnclave_init() { WhitelistOfAddrOutEnclave::init(); }

void WhitelistOfAddrOutEnclave_destroy() {
  WhitelistOfAddrOutEnclave::destroy();
}

void WhitelistOfAddrOutEnclave_add(const void *start, size_t size) {
  WhitelistOfAddrOutEnclave::add(start, size);
}

void WhitelistQuery(const void *ptr, size_t size, bool is_write,
                    bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return; // leave it to guard page check
  if (not is_write) {
    bool res = WhitelistOfAddrOutEnclave::double_fetch_detect(
        ptr, size, used_to_cmp, parent_func);
    sgxsan_warning(res, "Detect Double-Fetch Situation\n");
  }
  size_t find_size;
  std::tie(std::ignore, find_size, std::ignore) =
      WhitelistOfAddrOutEnclave::query(ptr, size);
  sgxsan_warning(find_size == 0, "Illegal access outside-enclave: 0x%p\n", ptr);
}

void WhitelistGlobalPropagate(const void *addr) {
  WhitelistOfAddrOutEnclave::global_propagate(addr);
}

void WhitelistActive() { WhitelistOfAddrOutEnclave::active(); }

void WhitelistDeactive() { WhitelistOfAddrOutEnclave::deactive(); }

void WhitelistAddInEnclaveAccessCnt() {
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
  WhitelistOfAddrOutEnclave::add_in_enclave_access_cnt();
#endif
}
