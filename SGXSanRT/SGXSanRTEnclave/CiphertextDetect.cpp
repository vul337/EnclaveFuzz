#include "CiphertextDetect.hpp"
#include "SGXSanRTCom.h"
#include "SGXSanRTTBridge.hpp"
#include "StackTrace.hpp"
#include <mbusafecrt.h>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <vector>

std::unordered_map<uint64_t /* callsite addr */,
                   std::vector<text_encryption_t> /* output type history */>
    output_history;

static pthread_rwlock_t rwlock_output_history = PTHREAD_RWLOCK_INITIALIZER;

static const unsigned int level = 2;

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

void __get_func_name(std::string &func_name_str) {
  uint64_t ret_addr = get_last_return_address(g_enclave_base, level + 2);
  size_t buf_size = 1024;
  char func_name[buf_size];
  memset(func_name, 0, buf_size);
  if (SGX_SUCCESS !=
      sgxsan_ocall_addr2func_name(ret_addr - 1, func_name, buf_size)) {
    abort();
  }
  func_name_str = func_name;
}

void draw_distribution(unsigned char *byte_arr, uint64_t size, int bucket_num,
                       bool is_cipher) {
  uint64_t ret_addr = get_last_return_address(g_enclave_base, level + 2);
  sgxsan_ocall_depcit_distribute(ret_addr - 1, byte_arr, size, bucket_num,
                                 is_cipher);
}

text_encryption_t isCiphertext(uint64_t addr, uint64_t size) {
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

  // draw_distribution((unsigned char *)addr, size, bucket_num, is_cipher);

  if (!is_cipher) {
    std::string func_name;
    __get_func_name(func_name);
    log_warning("[Cipher Detector] \'%s()\' plaintext transfering...\n",
                func_name.c_str());
  }
  return is_cipher ? Ciphertext : Plaintext;
}

void check_output_hybrid(uint64_t addr, uint64_t size) {
  pthread_rwlock_wrlock(&rwlock_output_history);

  // get history of callsite
  std::vector<text_encryption_t> &history =
      output_history[(get_last_return_address(g_enclave_base, level) - 1)];

  text_encryption_t status = isCiphertext(addr, size);
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