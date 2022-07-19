#include "OutAddrWhitelist.h"

thread_local std::map<const void *, size_t> OutAddrWhitelist::m_whitelist;
thread_local std::deque<FetchInfo> OutAddrWhitelist::m_control_fetchs;
__thread bool OutAddrWhitelist::m_active;
__thread bool OutAddrWhitelist::m_inited;
__thread size_t OutAddrWhitelist::m_out_enclave_access_cnt;
__thread size_t OutAddrWhitelist::m_in_enclave_access_cnt;
std::map<const void *, size_t> OutAddrWhitelist::m_global_whitelist;
pthread_rwlock_t OutAddrWhitelist::m_global_whitelist_rwlock;

// C Wrappers
void WhitelistAdd(const void *start, size_t size) {
  OutAddrWhitelist::add(start, size);
}

void WhitelistQuery(const void *ptr, size_t size, bool is_write,
                    bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return; // leave it to guard page check
  if (not is_write) {
    sgxsan_warning(OutAddrWhitelist::double_fetch_detect(ptr, size, used_to_cmp,
                                                         parent_func),
                   "Detect Double-Fetch Situation\n");
  }
  size_t find_size;
  std::tie(std::ignore, find_size, std::ignore) =
      OutAddrWhitelist::query(ptr, size);
  // sgxsan_warning(find_size == 0, "Illegal access outside-enclave: 0x%p\n",
  // ptr);
}

void WhitelistGlobalPropagate(const void *addr) {
  OutAddrWhitelist::global_propagate(addr);
}

void WhitelistActive() { OutAddrWhitelist::active(); }

void WhitelistDeactive() { OutAddrWhitelist::deactive(); }

void WhitelistAddInEnclaveAccessCnt() {
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
  OutAddrWhitelist::add_in_enclave_access_cnt();
#endif
}
