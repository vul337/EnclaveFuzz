#pragma once

#include "PoisonCheck.h"
#include "SGXSanRT.h"
#include <deque>
#include <map>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUNC_NAME_MAX_LEN 127
#define CONTROL_FETCH_QUEUE_MAX_SIZE 3

struct FetchInfo {
  const void *addr = nullptr;
  size_t size = 0;
  char funcName[FUNC_NAME_MAX_LEN + 1] = {'\0'};
  bool toCmp = false;
};

// Record Out-Enclave address in whitelist for each ECall
class OutAddrWhitelist {
public:
  // Called before root ECall
  static void init() {
    sgxsan_assert(m_whitelist.empty() and m_control_fetchs.empty() and
                  m_out_enclave_access_cnt == 0 and
                  m_in_enclave_access_cnt == 0 and m_active == false and
                  m_inited == false);
    m_inited = true;
  }

  // Called after root ECall return
  static void destroy() {
    sgxsan_assert(m_active == false);
    log_trace("[Access Count (Out/In)] %lld/%lld\n", m_out_enclave_access_cnt,
              m_in_enclave_access_cnt);
    m_out_enclave_access_cnt = 0;
    m_in_enclave_access_cnt = 0;
    m_whitelist.clear();
    m_control_fetchs.clear();
    m_inited = false;
  }

  static void iter(bool is_global = false) {
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
    auto &whitelist = is_global ? m_global_whitelist : m_whitelist;
    log_trace("[Whitelist] [%s(0x%p)] ", is_global ? "Global" : "Thread",
              &whitelist);
    for (auto &item : whitelist) {
      log_trace("0x%p(0x%llx) ", item.first, item.second);
    }
    log_trace("\n");
#else
    (void)is_global;
#endif
  }

  static std::pair<uptr, size_t>
  merge_adjacent_memory(uptr addr1, size_t len1, uptr addr2, size_t len2) {
    sgxsan_assert(addr1 && addr2 && len1 && len2);
    uptr result_addr = 0;
    size_t result_len = 0;

    if (addr1 <= addr2 && addr2 + len2 <= addr1 + len1) {
      // region2 is totally in region 1, or region1 is equal to region2
      result_addr = addr1;
      result_len = len1;
    } else if (addr2 < addr1 && addr1 + len1 < addr2 + len2) {
      // region1 is totally in region2
      result_addr = addr2;
      result_len = len2;
    } else if (addr1 <= addr2 && addr2 <= addr1 + len1) {
      // start from region1, end with region2
      result_addr = addr1;
      result_len = addr2 + len2 - addr1;
    } else if (addr2 <= addr1 && addr1 <= addr2 + len2) {
      // start from region2, end with region1
      result_addr = addr2;
      result_len = addr1 + len1 - addr2;
    }
    // not overlap at all
    return std::pair<uptr, size_t>(result_addr, result_len);
  }

  static void add(const void *ptr, size_t size) {
    // there may be ocall and ocall return before enter first ecall
    if (m_inited == false)
      return;
    sgxsan_assert(ptr && size > 0 && !m_active &&
                  sgx_is_outside_enclave(ptr, size));
    iter();
    log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread",
              &m_whitelist, "+?", ptr, size);
    const void *target_addr = ptr;
    size_t target_len = size;
    bool hasMet = false;
    for (auto it = m_whitelist.begin(); it != m_whitelist.end();) {
      auto tmp = merge_adjacent_memory((uptr)target_addr, target_len,
                                       (uptr)it->first, it->second);
      if (tmp.second != 0) {
        // overlap
        hasMet = true;
        log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread",
                  m_whitelist, "-", it->first, it->second);
        it = m_whitelist.erase(it);
        target_addr = (void *)tmp.first;
        target_len = tmp.second;
      } else if (hasMet)
        // already met overlapped region and subsequent regions will never
        // overlap any more
        break;
      else
        it++;
    }
    log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread",
              &m_whitelist, "+", target_addr, target_len);
    sgxsan_assert(m_whitelist.emplace(target_addr, target_len).second);
    iter();
  }

  static void add_global(const void *ptr, size_t size) {
    sgxsan_assert(ptr && size > 0 && sgx_is_outside_enclave(ptr, size));
    pthread_rwlock_wrlock(&m_global_whitelist_rwlock);
    iter(true);
    log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "+?", ptr, size);
    const void *target_addr = ptr;
    size_t target_len = size;
    bool hasMet = false;
    for (auto it = m_global_whitelist.begin();
         it != m_global_whitelist.end();) {
      auto tmp = merge_adjacent_memory((uptr)target_addr, target_len,
                                       (uptr)it->first, it->second);
      if (tmp.second != 0) {
        // overlap
        hasMet = true;
        log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "-",
                  it->first, it->second);
        it = m_global_whitelist.erase(it);
        target_addr = (void *)tmp.first;
        target_len = tmp.second;
      } else if (hasMet)
        break;
      else
        it++;
    }
    log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "+", target_addr,
              target_len);
    m_global_whitelist.emplace(target_addr, target_len);
    iter(true);
    pthread_rwlock_unlock(&m_global_whitelist_rwlock);
  }

  /*! \retval 1) query failed at thread and global whitelist
   * \retval 2) query success at thread whitelist (global whitelist may also
   * contain this info)
   * \retval 3) query success at global whitelist (thread
   * whitelist do not contain this info) */
  static std::tuple<const void *, size_t, bool /* atGlobal */>
  query(const void *ptr, size_t size) {
    std::tuple<const void *, size_t, bool> ret,
        ignore_ret = std::tuple<const void *, size_t, bool>(nullptr, 1, false),
        false_ret = std::tuple<const void *, size_t, bool>(nullptr, 0, false);
    if (ptr == nullptr)
      return false_ret;
    sgxsan_assert(ptr && size && sgx_is_outside_enclave(ptr, size));
    // there may be ocall and ocall return before enter first ecall, or query at
    // hooked memory intrinsics
    if (not m_inited or not m_active)
      return ignore_ret;
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
    m_out_enclave_access_cnt++;
#endif
    log_trace("[Whitelist] [%s(0x%p) %s] 0x%p(0x%llx)\n", "Thread",
              &m_whitelist, "?", ptr, size);

    iter();

    // find in thread whitelist
    if (m_whitelist.empty()) {
      ret = false_ret;
    } else {
      auto it = m_whitelist.lower_bound(ptr);
      if (LIKELY(it != m_whitelist.end() and it->first == ptr)) {
        // just found
        ret = it->second < size ? false_ret
                                : std::tuple<const void *, size_t, bool>(
                                      it->first, it->second, false);
      } else if (it != m_whitelist.begin()) {
        // get the element just blow query addr
        --it;
        ret = (uptr)it->first + it->second < (uptr)ptr + size
                  ? false_ret
                  : std::tuple<const void *, size_t, bool>(it->first,
                                                           it->second, false);
      } else {
        // there is no <addr,size> pair can contain the query addr
        ret = false_ret;
      }
    }

    // whether found in thread whitelist
    if (ret == false_ret) {
      // find in global whitelist
      auto global_query_ret = query_global(ptr, size);
      if (global_query_ret.second != 0) {
        ret = std::tuple<const void *, size_t, bool>(
            global_query_ret.first, global_query_ret.second, true);
      }
    }

    return ret;
  }

  static std::pair<const void *, size_t> query_global(const void *ptr,
                                                      size_t size) {
    pthread_rwlock_rdlock(&m_global_whitelist_rwlock);
    log_trace("[Whitelist] [%s %s] 0x%p(0x%llx)\n", "Global", "?", ptr, size);
    iter(true);
    std::pair<const void *, size_t> ret,
        false_ret = std::pair<const void *, size_t>(nullptr, 0);

    if (m_global_whitelist.empty()) {
      ret = false_ret;
    } else {
      auto it = m_global_whitelist.lower_bound(ptr);
      if (LIKELY(it != m_global_whitelist.end() and it->first == ptr)) {
        // just found
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
    }
    pthread_rwlock_unlock(&m_global_whitelist_rwlock);
    return ret;
  }

  // input ptr may be in Enclave or out of Enclave
  static void global_propagate(const void *ptr) {
    sgxsan_assert(m_inited and m_active);
    if (sgx_is_within_enclave(ptr, 1))
      return;
    const void *find_start = nullptr;
    size_t find_size = 0;
    bool is_at_global = false;
    std::tie(find_start, find_size, is_at_global) = query(ptr, 1);
    if (is_at_global == false && find_size != 0) {
      // found in thread whitelist
      sgxsan_assert(sgx_is_outside_enclave(find_start, find_size));
      log_trace("[Whitelist] [Thread(0x%p)] => 0x%p => [Global]\n", m_whitelist,
                ptr);
      add_global(find_start, find_size);
    }
  }
  static void active() { m_active = true; }
  static void deactive() { m_active = false; }

  // fetch must be a LoadInst
  static bool double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp, char *funcName) {
    sgxsan_assert(ptr && size && sgx_is_outside_enclave(ptr, size));
    // there may be ocall and ocall return before enter first ecall, or in
    // hooked mem intrinsics
    if (not m_inited or not m_active)
      return false;
    if (used_to_cmp) {
      // it's a fetch used to compare, maybe used to 'check'
      while (m_control_fetchs.size() >= CONTROL_FETCH_QUEUE_MAX_SIZE) {
        m_control_fetchs.pop_front();
      }
      FetchInfo info;
      info.addr = ptr;
      info.size = size;
      info.toCmp = used_to_cmp;
      strncpy(info.funcName, funcName,
              std::min((size_t)FUNC_NAME_MAX_LEN, strlen(funcName)));
      info.funcName[FUNC_NAME_MAX_LEN] = 0;
      m_control_fetchs.push_back(info);
      return false;
    } else {
      bool result = false;
      // it's a non-compared fetch, maybe used to 'use'
      for (auto &control_fetch : m_control_fetchs) {
        // if parent function name is not known, assume at same function and
        // only check overlap
        bool at_same_func = true;
        if (funcName)
          at_same_func = strncmp(control_fetch.funcName, funcName,
                                 std::min((size_t)FUNC_NAME_MAX_LEN,
                                          strlen(funcName))) == 0;
        bool is_overlap =
            RangesOverlap((const char *)control_fetch.addr, control_fetch.size,
                          (const char *)ptr, size);
        if (at_same_func and is_overlap) {
          result = true;
          break;
        }
      }
      return result;
    }
  }

  static void add_in_enclave_access_cnt() {
    if (m_inited and m_active) {
      m_in_enclave_access_cnt++;
    }
  }

private:
  static thread_local std::map<const void *, size_t> m_whitelist;
  static thread_local std::deque<FetchInfo> m_control_fetchs;
  // used in nested ecall-ocall case
  static __thread bool m_active;
  static __thread bool m_inited;
  static __thread size_t m_out_enclave_access_cnt;
  static __thread size_t m_in_enclave_access_cnt;
  static std::map<const void *, size_t> m_global_whitelist;
  static pthread_rwlock_t m_global_whitelist_rwlock;
};

// Callback of SGXSan
#if defined(__cplusplus)
extern "C" {
#endif

void WhitelistAdd(const void *start, size_t size);
void WhitelistQuery(const void *start, size_t size, bool is_write,
                    bool used_to_cmp = false, char *parent_func = nullptr);
void WhitelistGlobalPropagate(const void *addr);
void WhitelistAddInEnclaveAccessCnt();
void WhitelistActive();
void WhitelistDeactive();
#if defined(__cplusplus)
}
#endif
