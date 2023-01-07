#include "libFuzzerCallback.h"
#include "FuzzedDataProvider.h"
#include "RandPool.h"
#include <array>
#include <assert.h>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ostream>
#include <random>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using ordered_json = nlohmann::ordered_json;
namespace po = boost::program_options;

RandPool gRandPool;

sgx_enclave_id_t global_eid = 0;
std::string ClEnclaveFileName;
size_t ClMaxStrlen;
size_t ClMaxCount;
size_t ClMaxSize;
int ClUsedLogLevel;
bool ClProvideNullPointer;
double ClProvideNullPointerProbability;
double ClReturn0Probability;

// Fuzz sequence
enum FuzzMode { TEST_RANDOM, TEST_USER };
static std::vector<int> gFuzzerSeq;
static std::vector<int> gFilterOutIndices;
static FuzzMode gFuzzMode;

// Passed from DriverGen IR pass
extern sgx_status_t (*sgx_fuzzer_ecall_array[])();
extern int sgx_fuzzer_ecall_num;
extern char *sgx_fuzzer_ecall_wrapper_name_array[];

// log util
static const char *log_level_to_prefix[] = {
    "",
    "[SGXFuzz error] ",
    "[SGXFuzz warning] ",
    "[SGXFuzz debug] ",
    "[SGXFuzz trace] ",
};

// https://stackoverflow.com/questions/24686846/get-current-time-in-milliseconds-or-hhmmssmmm-format
std::string time_in_HH_MM_SS_MMM() {
  using namespace std::chrono;

  // get current time
  auto now = system_clock::now();

  // get number of milliseconds for the current second
  // (remainder after division into seconds)
  auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

  // convert to std::time_t in order to convert to std::tm (broken time)
  auto timer = system_clock::to_time_t(now);

  // convert to broken time
  std::tm bt = *std::localtime(&timer);

  std::ostringstream oss;

  oss << std::put_time(&bt, "%F %T"); // HH:MM:SS
  oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

  return oss.str();
}

void sgxfuzz_log(log_level level, bool with_prefix, const char *format, ...) {
  if (level > ClUsedLogLevel)
    return;

  // get prefix
  std::string prefix = "";
  if (with_prefix) {
    prefix += std::string(log_level_to_prefix[level]) + "[" +
              time_in_HH_MM_SS_MMM() + "] ";
  }
  std::cerr << prefix;

  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

// DataFactory Util
enum FuzzDataTy {
  FUZZ_STRING,
  FUZZ_WSTRING,
  FUZZ_DATA,
  FUZZ_ARRAY,
  FUZZ_SIZE,
  FUZZ_COUNT,
  FUZZ_RET,
  FUZZ_BOOL_SET_NULL,
  FUZZ_SEQ,
};

class FuzzDataFactory {
public:
  /// @brief fill random data in memory pointed by \p dst
  /// @param dst must be a valid memory area
  /// @param size memory area size
  void fillRand(void *dst, size_t size) {
    size_t step_times = size / sizeof(int), remained = size % sizeof(int);
    int *ptr_i32 = (int *)dst;
    for (size_t step = 0; step < step_times; step++) {
      ptr_i32[step] = rand();
    }
    if (remained > 0) {
      uint8_t *ptr_remained =
          (uint8_t *)((uint64_t)dst + step_times * sizeof(int));
      int rand_res = rand();
      for (size_t i = 0; i < remained; i++) {
        ptr_remained[i] = (rand_res >> (i * 8)) & 0xFF;
      }
    }
  }

  void NeedMoreFuzzData(size_t size) { mExpectedFuzzDataSize += size; }

  size_t mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    size_t NewSize = std::min(std::max(mExpectedFuzzDataSize, Size), MaxSize);
    sgxfuzz_assert(NewSize >= Size);
    fillRand(Data + Size, NewSize - Size);
    LLVMFuzzerMutate(Data, NewSize, MaxSize);
    return NewSize;
  }

  uint8_t *getBytes(uint8_t *dst, size_t bytesNum, FuzzDataTy dataTy) {
    if (bytesNum == 0 and dataTy != FUZZ_STRING and dataTy != FUZZ_WSTRING) {
      // Do nothing
      return dst;
    }

    switch (dataTy) {
    case FUZZ_ARRAY:
    case FUZZ_DATA: {
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      size_t wrCnt = 0;
      if (provider->remaining_bytes() > 0) {
        wrCnt = provider->ConsumeData(dst, bytesNum);
      }
      if (wrCnt < bytesNum) {
        gRandPool.getBytes(dst, bytesNum - wrCnt);
        NeedMoreFuzzData(bytesNum - wrCnt);
      }
      break;
    }
    case FUZZ_RET: {
      bool return0;
      if (provider->remaining_bytes() > 0) {
        double prob = 1 - provider->ConsumeProbability<double>();
        return0 = prob < ClReturn0Probability;
      } else {
        NeedMoreFuzzData(sizeof(uint64_t));
        return0 = false;
      }
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      if (return0) {
        memset(dst, 0, bytesNum);
      } else {
        size_t wrCnt = 0;
        if (provider->remaining_bytes() > 0) {
          wrCnt = provider->ConsumeData(dst, bytesNum);
        }
        if (wrCnt < bytesNum) {
          gRandPool.getBytes(dst, bytesNum - wrCnt);
          NeedMoreFuzzData(bytesNum - wrCnt);
        }
      }
      break;
    }
    case FUZZ_WSTRING: {
      // Get string length
      size_t givedStrlen;
      if (provider->remaining_bytes() > 0) {
        givedStrlen = provider->ConsumeIntegralInRange<size_t>(0, ClMaxStrlen);
      } else {
        givedStrlen = ClMaxStrlen;
        NeedMoreFuzzData(sizeof(size_t));
      }
      // Get string
      if (provider->remaining_bytes() > 0) {
        auto wstr =
            provider->ConsumeBytes<uint8_t>(givedStrlen * sizeof(wchar_t));
        if (wstr.size() < givedStrlen * sizeof(wchar_t)) {
          NeedMoreFuzzData(givedStrlen * sizeof(wchar_t) - wstr.size());
        }
        size_t wstrlen = (wstr.size() + sizeof(wchar_t) - 1) / sizeof(wchar_t);
        if (dst == nullptr) {
          dst = (uint8_t *)managedMalloc((wstrlen + 1) * sizeof(wchar_t));
        }
        memcpy(dst, wstr.data(), wstr.size());
        ((wchar_t *)dst)[wstrlen] = 0;
      } else {
        if (dst == nullptr) {
          dst = (uint8_t *)managedMalloc((givedStrlen + 1) * sizeof(wchar_t));
        }
        gRandPool.getBytes(dst, givedStrlen * sizeof(wchar_t));
        ((wchar_t *)dst)[givedStrlen] = 0;
        NeedMoreFuzzData(givedStrlen * sizeof(wchar_t));
      }
      break;
    }
    case FUZZ_STRING: {
      // Get string length
      size_t givedStrlen;
      if (provider->remaining_bytes() > 0) {
        givedStrlen = provider->ConsumeIntegralInRange<size_t>(0, ClMaxStrlen);
      } else {
        givedStrlen = ClMaxStrlen;
        NeedMoreFuzzData(sizeof(size_t));
      }
      // Get string
      if (provider->remaining_bytes() > 0) {
        std::string str = provider->ConsumeBytesAsString(givedStrlen);
        if (str.size() < givedStrlen) {
          NeedMoreFuzzData(givedStrlen - str.size());
        }
        if (dst == nullptr)
          dst = (uint8_t *)managedMalloc(str.size() + 1);
        memcpy(dst, str.data(), str.size());
        ((char *)dst)[str.size()] = 0;
      } else {
        // If data remained is not enough, get from fixed random pool
        if (dst == nullptr)
          dst = (uint8_t *)managedMalloc(givedStrlen + 1);
        gRandPool.getBytes(dst, givedStrlen);
        ((char *)dst)[givedStrlen] = 0;
        NeedMoreFuzzData(givedStrlen);
      }
      break;
    }
    case FUZZ_SIZE:
    case FUZZ_COUNT: {
      sgxfuzz_assert((bytesNum <= sizeof(size_t)));
      size_t data = 0;
      if (provider->remaining_bytes() > 0) {
        data = provider->ConsumeIntegralInRange<size_t>(
            0, dataTy == FUZZ_SIZE ? ClMaxSize : ClMaxCount);
      } else {
        // No data prepared, get from fixed random pool
        // assume little endian
        gRandPool.getBytes(&data, sizeof(size_t));
        size_t maxValue = (dataTy == FUZZ_SIZE ? ClMaxSize : ClMaxCount);
        data %= (maxValue + 1);
        NeedMoreFuzzData(sizeof(size_t));
      }
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      memcpy(dst, &data, bytesNum);
      break;
    }
    default:
      sgxfuzz_error(true, "Unsupported FUZZ_XXX type\n");
    }
    return dst;
  }

  size_t getUserCheckCount() {
    size_t res;
    if (provider->remaining_bytes() > 0) {
      res = provider->ConsumeIntegralInRange<size_t>(0, ClMaxCount);
    } else {
      res = ClMaxCount;
      NeedMoreFuzzData(sizeof(size_t));
    }
    return res;
  }

  bool EnableSetNull() {
    if (provider->remaining_bytes() > 0) {
      auto prob = 1.0 - provider->ConsumeProbability<double>();
      return prob <= ClProvideNullPointerProbability;
    } else {
      NeedMoreFuzzData(sizeof(uint64_t));
      return false;
    }
  }

  void init(const uint8_t *Data, size_t Size) {
    provider = new FuzzedDataProvider(Data, Size);
    mExpectedFuzzDataSize = Size;
  }

  void clear() {
    delete provider;
    for (auto memArea : allocatedMemAreas) {
      // log_debug("free %p\n", memArea);
      free(memArea);
    }
    allocatedMemAreas.clear();
  }

  void *managedMalloc(size_t size) {
    if (size == 0)
      return nullptr;
    void *ptr = malloc(size);
    sgxfuzz_assert(ptr != nullptr);
    // log_debug("malloc %p(%d)\n", ptr, size);
    allocatedMemAreas.push_back((uint8_t *)ptr);
    return ptr;
  }

  char *managedStr2CStr(std::string str) {
    char *cStr = (char *)managedMalloc(str.length() + 1);
    memcpy(cStr, str.c_str(), str.length());
    cStr[str.length()] = '\0';
    return cStr;
  }

  void getCallSequence(std::vector<int> &intCallSeq, size_t funcNum) {
    std::vector<int> callSeq(funcNum);
    std::iota(callSeq.begin(), callSeq.end(), 0);
    while (provider->remaining_bytes() > 0 and callSeq.size() > 0) {
      int idx = provider->ConsumeIntegralInRange<int>(0, callSeq.size() - 1);
      intCallSeq.push_back(callSeq[idx]);
      callSeq.erase(callSeq.begin() + idx);
    }
    for (auto id : callSeq) {
      NeedMoreFuzzData(sizeof(int));
      intCallSeq.push_back(id);
    }
  }

private:
  FuzzedDataProvider *provider;
  std::vector<uint8_t *> allocatedMemAreas;
  size_t mExpectedFuzzDataSize;
};
FuzzDataFactory data_factory;

void ShowAllECalls() {
  log_always("[Init] Num of ECall: %d\n", sgx_fuzzer_ecall_num);
  std::string ecalls;
  for (int i = 0; i < sgx_fuzzer_ecall_num; i++) {
    ecalls += std::string("  " + std::to_string(i) + " - " +
                          sgx_fuzzer_ecall_wrapper_name_array[i]) +
              "\n";
  }
  log_always("ECalls:\n%s\n", ecalls.c_str());
}

// libFuzzer Callbacks
extern "C" {

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  ShowAllECalls();

  // default mode is random
  gFuzzMode = TEST_RANDOM;

  // Declare the supported options.
  po::options_description desc("LibFuzzerCallback's inner options");
  auto add_opt = desc.add_options();
  add_opt("cb_help", "produce help message");
  add_opt("cb_enclave_file_name",
          po::value<std::string>(&ClEnclaveFileName)
              ->default_value("enclave.signed.so"),
          "Name of target Enclave file");
  add_opt(
      "cb_max_count", po::value<size_t>(&ClMaxCount)->default_value(4096),
      "Max count of elements for pointer which size is unknown or not fixed, "
      "if set too large, multi-level pointer will consume a large memory");
  add_opt("cb_max_size", po::value<size_t>(&ClMaxSize)->default_value(65536),
          "Max size of pointer element");
  add_opt("cb_max_str_len",
          po::value<size_t>(&ClMaxStrlen)->default_value(4096),
          "Max length of string");
  add_opt("cb_filter_out", po::value<std::string>(),
          "Specified ECalls that we don't test");
  add_opt("sgxfuzz_test_user",
          po::value<std::vector<std::string>>()->multitoken(),
          "test a number of APIs user specified");
  add_opt("cb_log_level", po::value<int>(&ClUsedLogLevel)->default_value(2),
          "0-Always, 1-Error, 2-Warning(Default), 3-Debug, 4-Trace");
  add_opt("cb_provide_nullptr",
          po::value<bool>(&ClProvideNullPointer)->default_value(true),
          "Provide NULL for fuzzed pointer parameter");
  add_opt(
      "cb_provide_nullptr_probability",
      po::value<double>(&ClProvideNullPointerProbability)->default_value(0.01),
      "The minimum granularity is 0.01 (1%)");
  add_opt("cb_return0_probability",
          po::value<double>(&ClReturn0Probability)->default_value(0.01),
          "The minimum granularity is 0.01 (1%)");

  po::variables_map vm;
  po::parsed_options parsed = po::command_line_parser(*argc, *argv)
                                  .options(desc)
                                  .allow_unregistered()
                                  .run();
  std::vector<std::string> to_pass_further =
      collect_unrecognized(parsed.options, po::include_positional);
  po::store(parsed, vm);
  po::notify(vm);

  // process options
  if (vm.count("cb_help")) {
    std::stringstream ss;
    ss << desc << "\n";
    log_always(ss.str().c_str());
    exit(0);
  }

  if (vm.count("sgxfuzz_test_user")) {
    gFuzzMode = TEST_USER;
    std::vector<std::string> indicesVec =
        vm["sgxfuzz_test_user"].as<std::vector<std::string>>();
    for (auto indices : indicesVec) {
      std::vector<std::string> indexVec;
      boost::split(indexVec, indices, [](char c) { return c == ','; });
      for (auto index : indexVec) {
        boost::trim(index);
        if (index == "")
          continue;
        gFuzzerSeq.push_back(std::stoi(index, 0, 0));
      }
    }

    log_always("Test user specified:");
    for (auto id : gFuzzerSeq) {
      log_always_np(" %d", id);
    }
    log_always_np("\n");
  }

  if (vm.count("cb_filter_out")) {
    std::string fiterOutECalls = vm["cb_filter_out"].as<std::string>();
    std::vector<std::string> fiterOutECallVec;
    boost::split(fiterOutECallVec, fiterOutECalls,
                 [](char c) { return c == ','; });

    std::map<std::string, int> wrapperName2Idx;
    for (int i = 0; i < sgx_fuzzer_ecall_num; i++) {
      wrapperName2Idx[sgx_fuzzer_ecall_wrapper_name_array[i]] = i;
    }

    for (auto fiterOutECall : fiterOutECallVec) {
      boost::trim(fiterOutECall);
      if (fiterOutECall == "") {
        continue;
      }
      std::string fuzzWrapperPrefix = "fuzz_";
      if (wrapperName2Idx.count(fuzzWrapperPrefix + fiterOutECall)) {
        size_t fiterOutECallIdx =
            wrapperName2Idx[fuzzWrapperPrefix + fiterOutECall];
        gFilterOutIndices.push_back(fiterOutECallIdx);
      }
    }
    log_always("Filter out:");
    for (auto filterOutIdx : gFilterOutIndices) {
      log_always_np(" %d", filterOutIdx);
    }
    log_always_np("\n");
  }
  sgxfuzz_assert(ClUsedLogLevel <= 4);
  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  return data_factory.mutate(Data, Size, MaxSize);
}

void LLVMFuzzerEarlyAfterRunOne() {
  // Destroy Enclave
  sgxfuzz_error(sgx_destroy_enclave(global_eid) != SGX_SUCCESS,
                "[FAIL] Enclave destroy");
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  data_factory.init(Data, Size);

  // Initialize Enclave
  sgx_status_t ret = sgx_create_enclave(
      ClEnclaveFileName.c_str(), SGX_DEBUG_FLAG /* Debug Support: set to 1 */,
      NULL, NULL, &global_eid, NULL);
  sgxfuzz_error(ret != SGX_SUCCESS, "[FAIL] Enclave initilize");

  // Test body
  std::vector<int> callSeq;
  if (gFuzzMode == TEST_USER) {
    callSeq = gFuzzerSeq;
  } else {
    data_factory.getCallSequence(callSeq, sgx_fuzzer_ecall_num);
  }
  for (int i : callSeq) {
    sgxfuzz_assert(i < sgx_fuzzer_ecall_num);
    if (std::find(gFilterOutIndices.begin(), gFilterOutIndices.end(), i) !=
        gFilterOutIndices.end()) {
      // Filter it out
      continue;
    }

    log_trace("[TEST] ECall-%d: %s\n", i,
              sgx_fuzzer_ecall_wrapper_name_array[i]);
    ret = sgx_fuzzer_ecall_array[i]();
    sgxfuzz_error(ret != SGX_SUCCESS and ret != SGX_ERROR_INVALID_PARAMETER and
                      ret != SGX_ERROR_ECALL_NOT_ALLOWED,
                  "[FAIL] ECall: %s", sgx_fuzzer_ecall_wrapper_name_array[i]);
  }

  data_factory.clear();
  return 0;
}

// DriverGen Callbacks
size_t DFGetUserCheckCount(size_t eleSize, char *cStrAsParamID) {
  return data_factory.getUserCheckCount();
}

uint8_t *DFGetBytesEx(uint8_t *ptr, size_t byteArrLen, char *cStrAsParamID,
                      FuzzDataTy dataType) {
  return data_factory.getBytes(ptr, byteArrLen, dataType);
}

uint8_t *DFGetBytes(size_t byteArrLen, char *cStrAsParamID,
                    FuzzDataTy dataType) {
  return data_factory.getBytes(nullptr, byteArrLen, dataType);
}

bool DFEnableSetNull(char *cStrAsParamID) {
  return ClProvideNullPointer ? data_factory.EnableSetNull() : false;
}

void *DFManagedMalloc(size_t size) { return data_factory.managedMalloc(size); }

uint64_t getPointToCount(uint64_t size, uint64_t count, uint64_t eleSize) {
  sgxfuzz_assert(eleSize);
  // Maybe size * count != n * eleSize, due to problem of Enclave developer
  uint64_t ptCnt = (size * count + eleSize - 1) / eleSize;
  return std::max(ptCnt, (uint64_t)1);
}
}