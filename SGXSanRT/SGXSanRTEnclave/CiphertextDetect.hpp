#pragma once

#include "SGXSanRTCom.h"
#include "SGXSanRTTBridge.hpp"
#include "StackTrace.hpp"
#include <mbusafecrt.h>
#include <pthread.h>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

typedef enum text_encryption {
  Unknown,
  Plaintext,
  Ciphertext
} text_encryption_t;

extern std::unordered_map<
    uint64_t /* callsite addr */,
    std::vector<text_encryption_t> /* output type history */>
    output_history;
extern pthread_rwlock_t rwlock_output_history;

static inline int getArraySum(int *array, int size) {
  int sum = 0;
  for (int i = 0; i < size; i++) {
    sum += array[i];
  }
  return sum;
}

static inline int getBucketNum(size_t size) {
  return size >= 0x800   ? 0x100
         : size >= 0x100 ? 0x40
         : size >= 0x10  ? 0x4
         : size >= 0x2   ? 0x2
                         : 0x1;
}

__attribute__((always_inline)) static inline text_encryption_t
isCiphertext(uint64_t addr, uint64_t size, uint64_t caller_addr) {
  if (size < 0x100)
    return Unknown;

  int bucket_num = getBucketNum(size);

  int map[256 /* 2^8 */] = {0};

  // collect byte map
  for (uint64_t i = 0; i < size; i++) {
    unsigned char byte = *(unsigned char *)(addr + i);
    map[byte]++;
  }

  double CountPerBacket = (int)size / (double)bucket_num;
  if (size >= 0x100)
    CountPerBacket = (int)(size - map[0] /* maybe 0-padding in ciphertext */) /
                     (double)(bucket_num - 1);

  bool is_cipher = true;
  int step = 0x100 / bucket_num;
  log_trace("[Cipher Detect] CountPerBacket = %f \n", CountPerBacket);

  for (int i = 0; i < 256; i += step) {
    int sum = getArraySum(map + i, step);
    if ((sum > CountPerBacket * 1.5 || sum < CountPerBacket / 2) and
        (size >= 0x100 ? i != 0 : true)) {
      is_cipher = false;
      break;
    }
  }

  // sgxsan_ocall_depcit_distribute(caller_addr, (unsigned char *)addr, size,
  //                                bucket_num, is_cipher);
  if (!is_cipher) {
    size_t buf_size = 1024;
    char func_name[buf_size];
    memset(func_name, 0, buf_size);
    if (SGX_SUCCESS !=
        sgxsan_ocall_addr2func_name(caller_addr, func_name, buf_size)) {
      abort();
    }
    log_warning("[Cipher Detector] \'%s()\' plaintext transfering...\n",
                func_name);
  }
  return is_cipher ? Ciphertext : Plaintext;
}

__attribute__((always_inline)) static inline void
check_output_hybrid(uint64_t addr, uint64_t size) {
  pthread_rwlock_wrlock(&rwlock_output_history);

  // get history of callsite
  const size_t depth = 2;
  std::vector<uint64_t> bt_addrs;
  libunwind_backtrace(bt_addrs, depth);
  if (bt_addrs.size() != depth)
    return;

  std::vector<text_encryption_t> &history =
      output_history[bt_addrs[depth - 1] - g_enclave_base - 1];

  text_encryption_t status =
      isCiphertext(addr, size, bt_addrs[depth - 1] - g_enclave_base);
  if (history.size() == 0) {
    history.emplace_back(status);
  } else {
    text_encryption_t last_known_status = Unknown;
    for (auto it = history.rbegin(); it != history.rend(); it++) {
      if (*it != Unknown) {
        last_known_status = *it;
        break;
      }
    }
    history.emplace_back(status);

    sgxsan_warning(last_known_status != Unknown && status != Unknown &&
                       last_known_status != status,
                   "Output is plaintext ciphertext hybridization\n");
  }
  pthread_rwlock_unlock(&rwlock_output_history);
}