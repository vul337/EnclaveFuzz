#include "libFuzzerCallback.h"
#include "FuzzDataType.h"
#include "FuzzedDataProvider.h"
#include "RandPool.h"
#include "magic_enum.hpp"
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
#include <filesystem>
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
#include <unordered_map>
#include <unordered_set>
#include <vector>

using ordered_json = nlohmann::ordered_json;
namespace po = boost::program_options;
namespace fs = std::filesystem;

RandPool gRandPool;

sgx_enclave_id_t global_eid = 0;
std::string ClEnclaveFileName;
size_t ClMaxStrlen, ClMaxCount, ClMaxSize, ClMaxCallSeqSize;
int ClUsedLogLevel;
double ClProvideNullPointerProb, ClReturn0Prob, ClModifyOCallRetProb;

// Fuzz sequence
enum FuzzMode { TEST_RANDOM, TEST_USER };
static std::vector<int> gFuzzerSeq;
static std::vector<int> gFilterOutIndices;
static FuzzMode gFuzzMode;
static std::unordered_map<std::string, FuzzDataTy> gSpecDataID2Type;

// Passed from DriverGen IR pass
extern sgx_status_t (*gFuzzECallArray[])();
extern int gFuzzECallNum;
extern char *gFuzzECallNameArray[];

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
class FuzzDataFactory {
public:
  /// @brief fill random data in memory pointed by \p dst
  /// @param dst must be a valid memory area
  /// @param size memory area size
  void fillRand(uint8_t *dst, size_t size) {
    std::random_device rd;
    std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> ibe(
        rd());
    std::generate(dst, dst + size, std::ref(ibe));
  }

  void NeedMoreFuzzData(size_t size) { mExpectedFuzzDataSize += size; }

  size_t mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    size_t NewSize = std::min(std::max(mExpectedFuzzDataSize, Size), MaxSize);
    sgxfuzz_assert(NewSize >= Size);
    if (NewSize > Size) {
      fillRand(Data + Size, NewSize - Size);
    }
    LLVMFuzzerMutate(Data, NewSize, MaxSize);
    return NewSize;
  }

  uint8_t *getBytes(uint8_t *dst, size_t bytesNum, FuzzDataTy dataTy) {
    if (bytesNum == 0 and dataTy != FUZZ_STRING and dataTy != FUZZ_WSTRING) {
      // Do nothing
      return dst;
    }

    switch (dataTy) {
    case FUZZ_P_DOUBLE: {
      sgxfuzz_assert(sizeof(double) == bytesNum);
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      if (provider->remaining_bytes() > 0) {
        provider->ConsumeFloatingPointInRange<double>(
            0, std::numeric_limits<double>::max());
      } else {
        gRandPool.getBytes(dst, bytesNum, mRandPoolBytesOffset++);
        NeedMoreFuzzData(sizeof(uint64_t));
        double *dst_double = (double *)dst;
        *dst_double = std::fabs(*dst_double);
      }
      break;
    }
    case FUZZ_ARRAY:
    case FUZZ_DATA: {
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      size_t wrCnt = 0;
      if (provider->remaining_bytes() > 0) {
        wrCnt = provider->ConsumeData(dst, bytesNum);
      }
      if (wrCnt < bytesNum) {
        gRandPool.getBytes(dst, bytesNum - wrCnt, mRandPoolBytesOffset++);
        NeedMoreFuzzData(bytesNum - wrCnt);
      }
      break;
    }
    case FUZZ_RET: {
      bool return0;
      if (provider->remaining_bytes() > 0) {
        double prob = 1 - provider->ConsumeProbability<double>();
        return0 = prob < ClReturn0Prob;
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
          gRandPool.getBytes(dst, bytesNum - wrCnt, mRandPoolBytesOffset++);
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
        givedStrlen = gRandPool.getIntergerInRange<size_t>(
            0, ClMaxStrlen, mRandPoolBytesOffset++);
        NeedMoreFuzzData(sizeof(size_t));
      }
      if (bytesNum != 0) {
        givedStrlen %= (bytesNum + 1);
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
        gRandPool.getBytes(dst, givedStrlen * sizeof(wchar_t),
                           mRandPoolBytesOffset++);
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
        givedStrlen = gRandPool.getIntergerInRange<size_t>(
            0, ClMaxStrlen, mRandPoolBytesOffset++);
        NeedMoreFuzzData(sizeof(size_t));
      }
      if (bytesNum != 0) {
        givedStrlen %= (bytesNum + 1);
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
        gRandPool.getBytes(dst, givedStrlen, mRandPoolBytesOffset++);
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
        gRandPool.getBytes(&data, sizeof(size_t), mRandPoolBytesOffset++);
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
      res = gRandPool.getIntergerInRange<size_t>(0, ClMaxCount,
                                                 mRandPoolBytesOffset++);
      NeedMoreFuzzData(sizeof(size_t));
    }
    return res;
  }

  bool EnableSetNull() {
    double prob;
    if (provider->remaining_bytes() > 0) {
      prob = 1.0 - provider->ConsumeProbability<double>();
    } else {
      NeedMoreFuzzData(sizeof(uint64_t));
      prob = gRandPool.getProbability(mRandPoolBytesOffset++);
    }
    return prob <= ClProvideNullPointerProb;
  }

  void init(const uint8_t *Data, size_t Size) {
    if (provider) {
      // Remove old
      delete provider;
    }
    provider = new FuzzedDataProvider(Data, Size);
    mExpectedFuzzDataSize = Size;
    mRandPoolBytesOffset = 0;
  }

  void clear() {
    // Don't delete provider here, since later sgx_destroy_enclave may use it
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

  void *managedCalloc(size_t count, size_t size) {
    if (count * size == 0)
      return nullptr;
    void *ptr = calloc(count, size);
    sgxfuzz_assert(ptr != nullptr);
    // log_debug("calloc %p(%d * %d)\n", ptr, count, size);
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
    // Get CallSeqSize
    size_t CallSeqSize;
    if (provider->remaining_bytes() > 0) {
      CallSeqSize =
          provider->ConsumeIntegralInRange<size_t>(1, ClMaxCallSeqSize);
    } else {
      NeedMoreFuzzData(sizeof(size_t));
      CallSeqSize = gRandPool.getIntergerInRange<size_t>(
          1, ClMaxCallSeqSize, mRandPoolBytesOffset++);
    }
    // Get CallSeq
    for (size_t i = 0; i < CallSeqSize; i++) {
      int idx;
      if (provider->remaining_bytes() > 0) {
        idx = provider->ConsumeIntegralInRange<int>(0, funcNum - 1);
      } else {
        NeedMoreFuzzData(sizeof(int));
        idx = gRandPool.getIntergerInRange<int>(0, funcNum - 1,
                                                mRandPoolBytesOffset++);
      }
      intCallSeq.push_back(idx);
    }
  }

  void AddNotModifyOCallRetSpecs(std::string ID) {
    mNotModifyOCallRetSpecs.emplace(ID);
  }

  bool EnableModifyOCallRet(char *cParamID) {
    std::string ParamID(cParamID);
    if (mNotModifyOCallRetSpecs.count(ParamID)) {
      return false;
    }
    double prob;
    if (provider->remaining_bytes() > 0) {
      prob = 1.0 - provider->ConsumeProbability<double>();
    } else {
      NeedMoreFuzzData(sizeof(uint64_t));
      prob = gRandPool.getProbability(mRandPoolBytesOffset++);
    }
    return prob <= ClModifyOCallRetProb;
  }

private:
  FuzzedDataProvider *provider;
  std::vector<uint8_t *> allocatedMemAreas;
  size_t mExpectedFuzzDataSize, mRandPoolBytesOffset;
  std::unordered_set<std::string> mNotModifyOCallRetSpecs;
};
FuzzDataFactory data_factory;

void ShowAllECalls() {
  log_always("[Init] Num of ECall: %d\n", gFuzzECallNum);
  std::string ecalls;
  for (int i = 0; i < gFuzzECallNum; i++) {
    ecalls +=
        std::string("  " + std::to_string(i) + " - " + gFuzzECallNameArray[i]) +
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
  add_opt("cb_help", "Produce help message");
  add_opt("cb_enclave",
          po::value<std::string>(&ClEnclaveFileName)
              ->default_value("enclave.signed.so"),
          "Name of target Enclave file");
  add_opt("cb_max_count", po::value<size_t>(&ClMaxCount)->default_value(65536),
          "Max count of elements for pointer");
  add_opt("cb_max_size", po::value<size_t>(&ClMaxSize)->default_value(65536),
          "Max size of pointer element");
  add_opt("cb_max_strlen",
          po::value<size_t>(&ClMaxStrlen)->default_value(65536),
          "Max length of string (no tail 0)");
  add_opt("cb_filter_out", po::value<std::string>(), "Don't test these ECalls");
  add_opt("sgxfuzz_test_user", po::value<std::string>(), "Test these ECalls");
  add_opt("cb_log_level", po::value<int>(&ClUsedLogLevel)->default_value(2),
          "0-Always, 1-Error, 2-Warning(Default), 3-Debug, 4-Trace");
  add_opt("cb_nullptr_prob",
          po::value<double>(&ClProvideNullPointerProb)->default_value(0.01),
          "Probability to provide null as fuzz data to pointer");
  add_opt("cb_return0_prob",
          po::value<double>(&ClReturn0Prob)->default_value(0.01),
          "Probability to return all 0 in OCall return");
  add_opt("cb_data_type", po::value<std::string>(),
          "Feed data with specified type (override default), ID=FUZZ_XXX[, "
          "...] , e.g. "
          "/untrusted/ocall_current_time/parameter/0=FUZZ_P_DOUBLE[,...]");
  add_opt("cb_ocall_ret_through", po::value<std::string>(),
          "Not modify OCall return value specified by ID, ID[,...] , e.g. "
          "/untrusted/ocall_current_time/parameter/0[,...]");
  add_opt("cb_ecall_queue_size",
          po::value<size_t>(&ClMaxCallSeqSize)->default_value(20),
          "Max ECall queue size");
  add_opt("cb_modify_ocall_ret_prob",
          po::value<double>(&ClModifyOCallRetProb)->default_value(0.5),
          "Probability to modify OCall return");

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
    log_always("%s", ss.str().c_str());
    exit(0);
  }

  if (vm.count("sgxfuzz_test_user")) {
    gFuzzMode = TEST_USER;
    std::string indexList = vm["sgxfuzz_test_user"].as<std::string>();
    std::vector<std::string> indexVec;
    boost::split(indexVec, indexList, [](char c) { return c == ','; });
    for (auto index : indexVec) {
      boost::trim(index);
      if (index != "") {
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
    for (int i = 0; i < gFuzzECallNum; i++) {
      wrapperName2Idx[gFuzzECallNameArray[i]] = i;
    }

    for (auto fiterOutECall : fiterOutECallVec) {
      boost::trim(fiterOutECall);
      if (fiterOutECall != "") {
        std::string fuzzWrapperPrefix = "fuzz_";
        if (wrapperName2Idx.count(fuzzWrapperPrefix + fiterOutECall)) {
          size_t fiterOutECallIdx =
              wrapperName2Idx[fuzzWrapperPrefix + fiterOutECall];
          gFilterOutIndices.push_back(fiterOutECallIdx);
        }
      }
    }
    log_always("Filter out:");
    for (auto filterOutIdx : gFilterOutIndices) {
      log_always_np(" %d", filterOutIdx);
    }
    log_always_np("\n");
  }

  if (vm.count("cb_data_type")) {
    std::string dataTySpecList = vm["cb_data_type"].as<std::string>();
    std::vector<std::string> dataTySpecVec;
    boost::split(dataTySpecVec, dataTySpecList,
                 [](char c) { return c == ','; });

    for (auto dataTySpec : dataTySpecVec) {
      boost::trim(dataTySpec);
      if (dataTySpec != "") {
        std::vector<std::string> pair;
        boost::split(pair, dataTySpec, [](char c) { return c == '='; });
        auto dataType = magic_enum::enum_cast<FuzzDataTy>(pair[1]);
        if (dataType.has_value()) {
          gSpecDataID2Type[pair[0]] = dataType.value();
        }
      }
    }
  }

  if (vm.count("cb_ocall_ret_through")) {
    std::string NotModifyOCallRetSpecList =
        vm["cb_ocall_ret_through"].as<std::string>();
    std::vector<std::string> NotModifyOCallRetSpecVec;
    boost::split(NotModifyOCallRetSpecVec, NotModifyOCallRetSpecList,
                 [](char c) { return c == ','; });

    for (auto NotModifyOCallRetSpec : NotModifyOCallRetSpecVec) {
      boost::trim(NotModifyOCallRetSpec);
      if (NotModifyOCallRetSpec != "") {
        data_factory.AddNotModifyOCallRetSpecs(NotModifyOCallRetSpec);
      }
    }
  }

  sgxfuzz_assert(ClUsedLogLevel <= 4);
  sgxfuzz_assert(ClMaxCallSeqSize >= 1);
  return 0;
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize,
                               unsigned int Seed) {
  return data_factory.mutate(Data, Size, MaxSize);
}

void LLVMFuzzerEarlyAfterRunOne() {
  // Destroy Enclave
  sgxfuzz_error(sgx_destroy_enclave(global_eid) != SGX_SUCCESS,
                "[FAIL] Enclave destroy");
}

extern "C" __attribute__((weak)) int SGXFuzzerEnvClearBeforeTest();
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Remove last round environment remain
  if (SGXFuzzerEnvClearBeforeTest) {
    sgxfuzz_assert(SGXFuzzerEnvClearBeforeTest() == 0);
  }
  // Remove last round backtrace.dump
  fs::remove(fs::path("backtrace.dump"));
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
    data_factory.getCallSequence(callSeq, gFuzzECallNum);
  }
  for (int i : callSeq) {
    sgxfuzz_assert(i < gFuzzECallNum);
    if (std::find(gFilterOutIndices.begin(), gFilterOutIndices.end(), i) !=
        gFilterOutIndices.end()) {
      // Filter it out
      continue;
    }

    log_trace("[TEST] ECall-%d: %s\n", i, gFuzzECallNameArray[i]);
    ret = gFuzzECallArray[i]();
    sgxfuzz_error(ret != SGX_SUCCESS and ret != SGX_ERROR_INVALID_PARAMETER and
                      ret != SGX_ERROR_ECALL_NOT_ALLOWED,
                  "[FAIL] ECall: %s", gFuzzECallNameArray[i]);
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

uint8_t *DFGetBytes(uint8_t *ptr, size_t byteArrLen, char *cStrAsParamID,
                    FuzzDataTy dataType) {
  // log_always("%s requires %llx bytes data\n", cStrAsParamID, byteArrLen);
  std::string ParamID(cStrAsParamID);
  // std::replace(ParamID.begin(), ParamID.end(), '/', '_');
  if (gSpecDataID2Type.count(ParamID)) {
    // Override DataType by user specified
    dataType = gSpecDataID2Type[ParamID];
  }
  return data_factory.getBytes(ptr, byteArrLen, dataType);
}

bool DFEnableSetNull(char *cStrAsParamID) {
  return data_factory.EnableSetNull();
}

void *DFManagedMalloc(size_t size) { return data_factory.managedMalloc(size); }
void *DFManagedCalloc(size_t count, size_t size) {
  return data_factory.managedCalloc(count, size);
}

uint64_t DFGetPtToCntECall(uint64_t size, uint64_t count, uint64_t eleSize) {
  sgxfuzz_assert(eleSize);
  // Maybe size * count != n * eleSize, due to problem of Enclave developer
  uint64_t ptCnt = (size * count + eleSize - 1) / eleSize;
  return ptCnt;
}

uint64_t DFGetPtToCntOCall(uint64_t size, uint64_t count, uint64_t eleSize) {
  sgxfuzz_assert(eleSize);
  // Maybe size * count != n * eleSize, due to problem of Enclave developer
  uint64_t ptCnt = (size * count) / eleSize;
  return ptCnt;
}

bool DFEnableModifyOCallRet(char *cParamID) {
  return data_factory.EnableModifyOCallRet(cParamID);
}
}