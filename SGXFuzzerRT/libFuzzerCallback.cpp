#include "libFuzzerCallback.h"
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <regex>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using ordered_json = nlohmann::ordered_json;

sgx_enclave_id_t global_eid = 0;

// Passed from DriverGen IR pass
extern sgx_status_t (*sgx_fuzzer_ecall_array[])();
extern int sgx_fuzzer_ecall_num;
extern char *sgx_fuzzer_ecall_wrapper_name_array[];

/// Used to leave \c LLVMFuzzerTestOneInput
jmp_buf sgx_fuzzer_jmp_buf;
void leaveLLVMFuzzerTestOneInput() { longjmp(sgx_fuzzer_jmp_buf, 0); }

// log util
static const char *log_level_to_prefix[] = {
    [LOG_LEVEL_ALWAYS] = "",
    [LOG_LEVEL_ERROR] = "[SGXFuzz error] ",
    [LOG_LEVEL_WARNING] = "[SGXFuzz warning] ",
    [LOG_LEVEL_DEBUG] = "[SGXFuzz debug] ",
    [LOG_LEVEL_TRACE] = "[SGXFuzz trace] ",
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
  if (level > USED_LOG_LEVEL)
    return;

  // get prefix
  std::string prefix = "";
  if (with_prefix) {
    prefix += std::string(log_level_to_prefix[level]) + "[" +
              time_in_HH_MM_SS_MMM() + "] ";
  }

  // get buf from format
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, format);
  vsnprintf(buf, BUFSIZ, format, ap);
  va_end(ap);
  // output
  std::cerr << prefix << std::string(buf) << std::endl;
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
  FUZZ_BOOL,
};

enum DataOp {
  DATA_EXPAND,
  DATA_SHRINK,
  DATA_CREATE,
  DATA_DESTROY,
};

struct RequestInfo {
  std::string StrAsID;
  DataOp op;
  size_t size;
  FuzzDataTy dataType;
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

  /// @brief fill random data in memory pointed by \p cStrBuf, and put \c '\0'
  /// in end
  /// @param cStrBuf must be a valid memory area
  /// @param size \p cStrBuf size
  template <class T> void fillStrRand(T *cStrBuf, size_t size) {
    fillRand(cStrBuf, (size - 1) * sizeof(T));
    cStrBuf[size] = '\0';
  }

  void insertItemInMutatorJSon(RequestInfo req) {
    nlohmann::ordered_json::json_pointer JSonPtr("/" + req.StrAsID);
    mutatorJson[JSonPtr / "DataType"] = req.dataType;
    switch (req.dataType) {
    case FUZZ_STRING: {
      sgxfuzz_assert(req.size == 0);
      size_t newStrLen = rand() % (MAX_STRING_LENGTH + 1);
      char newStr[newStrLen + 1];
      fillStrRand(newStr, newStrLen + 1);
      mutatorJson[JSonPtr / "Data"] = std::string(newStr);
      break;
    }
    case FUZZ_WSTRING: {
      sgxfuzz_assert(req.size == 0);
      size_t newStrLen = rand() % (MAX_STRING_LENGTH + 1);
      wchar_t newStr[newStrLen + 1];
      fillStrRand(newStr, newStrLen + 1);
      mutatorJson[JSonPtr / "Data"] = EncodeBase64(std::vector<uint8_t>(
          (uint8_t *)newStr,
          (uint8_t *)newStr + sizeof(wchar_t) * (newStrLen + 1)));
      break;
    }
    case FUZZ_COUNT:
    case FUZZ_SIZE: {
      size_t maxValue = req.dataType == FUZZ_SIZE ? MAX_SIZE : MAX_COUNT;
      sgxfuzz_assert(req.size < sizeof(size_t));
      size_t newData;
      fillRand(&newData, sizeof(size_t));
      newData %= (maxValue + 1);
      mutatorJson[JSonPtr / "Data"] = newData;
      break;
    }
    case FUZZ_RET:
    case FUZZ_ARRAY:
    case FUZZ_DATA: {
      uint8_t newData[req.size] = {0};
      fillRand(newData, req.size);
      mutatorJson[JSonPtr / "Data"] =
          EncodeBase64(std::vector<uint8_t>(newData, newData + req.size));
      break;
    }
    case FUZZ_BOOL: {
      mutatorJson[JSonPtr / "Data"] = (bool)(rand() % 100 < 20);
    }
    }
  }

  void dumpJson(ordered_json json);
  void dumpJsonPtr(ordered_json::json_pointer ptr);

  void AdjustItemInMutatorJSon(RequestInfo req) {
    ordered_json::json_pointer JSonPtr("/" + req.StrAsID);
    switch (req.dataType) {
    // should only expand byte array
    case FUZZ_ARRAY:
    case FUZZ_DATA: {
      auto data = DecodeBase64(mutatorJson[JSonPtr / "Data"]);
      AdjustNBytes(data, req.size, req.op);
      mutatorJson[JSonPtr / "Data"] = EncodeBase64(data);
      break;
    }
    default: {
      sgxfuzz_error(true, "Data to be adjust should only be byte array");
      break;
    }
    }
  }

  void AdjustNBytes(std::vector<uint8_t> &byteArr, size_t N, DataOp op) {
    auto adjustPt = byteArr.begin() + rand() % (byteArr.size());
    switch (op) {
    case DATA_EXPAND: {
      uint8_t newData[N];
      fillRand(newData, N);
      byteArr.insert(adjustPt, newData, newData + N);
      break;
    }
    case DATA_SHRINK: {
      byteArr.erase(adjustPt, adjustPt + N);
      break;
    }
    default: {
      sgxfuzz_error(true, "[AdjustNBytes] Unsupported DATA_{Operation}");
      break;
    }
    }
  }

  void mutateOnMutatorJSon(bool canChangeSize = true) {
    for (auto pair : mutatorJson.items()) {
      ordered_json::json_pointer ptr("/" + pair.key());
      FuzzDataTy dataTy = mutatorJson[ptr / "DataType"];
      switch (dataTy) {
      case FUZZ_STRING: {
        std::string data = mutatorJson[ptr / "Data"];
        size_t strLen = std::min(data.size(), (size_t)MAX_STRING_LENGTH);
        char buf[MAX_STRING_LENGTH + 1];
        memcpy(buf, data.c_str(), strLen);
        auto newLen =
            LLVMFuzzerMutate((uint8_t *)buf, strLen, MAX_STRING_LENGTH);
        assert(newLen <= MAX_STRING_LENGTH);
        buf[newLen] = '\0';
        mutatorJson[ptr / "Data"] = std::string(buf);
        break;
      }
      case FUZZ_WSTRING: {
        auto byteArr = DecodeBase64(std::string(mutatorJson[ptr / "Data"]));
        sgxfuzz_assert(byteArr.size() % sizeof(wchar_t) == 0);
        size_t wStrLen = std::min(byteArr.size() / sizeof(wchar_t),
                                  (size_t)MAX_STRING_LENGTH);
        wchar_t wStr[MAX_STRING_LENGTH + 1];
        memcpy(wStr, byteArr.data(), wStrLen);
        auto newLen =
            LLVMFuzzerMutate((uint8_t *)wStr, wStrLen, MAX_STRING_LENGTH);
        wStr[newLen] = '\0';
        mutatorJson[ptr / "Data"] =
            EncodeBase64(std::vector<uint8_t>(wStr, wStr + newLen + 1));
        break;
      }
      case FUZZ_SIZE:
      case FUZZ_COUNT: {
        if (canChangeSize) {
          size_t maxValue = dataTy == FUZZ_SIZE ? MAX_SIZE : MAX_COUNT;
          size_t data = mutatorJson[ptr / "Data"];
          switch (rand() % 2) {
          case 0x0:
            data = (data % maxValue) + 1;
            break;
          case 0x1:
            break;
          }
          mutatorJson[ptr / "Data"] = data;
        }
        break;
      }
      case FUZZ_ARRAY:
      case FUZZ_DATA:
      case FUZZ_RET: {
        auto byteArr = DecodeBase64(std::string(mutatorJson[ptr / "Data"]));
        uint8_t cByteArr[byteArr.size()];
        memcpy(cByteArr, byteArr.data(), byteArr.size());
        LLVMFuzzerMutate(cByteArr, byteArr.size(), byteArr.size());
        // Fixed-size mutate
        mutatorJson[ptr / "Data"] = EncodeBase64(
            std::vector<uint8_t>(cByteArr, cByteArr + byteArr.size()));
        break;
      }
      case FUZZ_BOOL: {
        mutatorJson[ptr / "Data"] = (bool)(rand() % 100 < 20);
      }
      }
    }
  }

  size_t mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    std::vector<uint8_t> bjdata(Data, Data + Size);
    try {
      mutatorJson = nlohmann::ordered_json::from_bjdata(bjdata);
    } catch (ordered_json::parse_error &e) {
      // leave mutatorJson empty, and it should be empty
      sgxfuzz_assert(mutatorJson.empty());
    }
    log_debug("[Before Mutate FuzzDataFactory::mutatorJson]");
    dumpJson(mutatorJson);
    if (reqQueue.empty()) {
      /// Arbitrarily mutate on \c mutatorJson
      mutateOnMutatorJSon();
    } else {
      // Mutate data except which is FUZZ_COUNT/FUZZ_SIZE type
      mutateOnMutatorJSon(false);
      /// process \c reqQueue
      while (not reqQueue.empty()) {
        RequestInfo req = reqQueue.back();
        reqQueue.pop_back();
        nlohmann::ordered_json::json_pointer jsonPtr("/" + req.StrAsID);
        switch (req.op) {
        case DATA_CREATE: {
          sgxfuzz_assert(mutatorJson[jsonPtr].is_null());
          insertItemInMutatorJSon(req);
          break;
        }
        case DATA_EXPAND:
        case DATA_SHRINK: {
          sgxfuzz_assert(not mutatorJson[jsonPtr].is_null());
          AdjustItemInMutatorJSon(req);
          break;
        }
        default: {
          sgxfuzz_error(true, "[mutate] Unsupported DATA_{Operation}");
          break;
        }
        }
      }
    }
    auto newBjData = nlohmann::ordered_json::to_bjdata(mutatorJson);
    sgxfuzz_assert(newBjData.size() <= MaxSize);
    memcpy(Data, newBjData.data(), newBjData.size());
    log_debug("[After Mutate FuzzDataFactory::mutatorJson]");
    dumpJson(mutatorJson);
    mutatorJson.clear();
    return newBjData.size();
  }

  void SendRequest(RequestInfo req) { reqQueue.push_back(req); }

  /// @brief get byte array from \c ConsumerJSon, and save it to \p dst. If no
  /// byte array prepared for current \p cStrAsID, \c SendRequest to mutator
  /// phase
  /// @param cStrAsID Using JSon pointer string as ID
  /// @param dst A pre-allocated memory area
  /// @param byteArrLen
  /// @param dataTy
  /// @return
  uint8_t *getBytes(const char *cStrAsID, uint8_t *dst, size_t byteArrLen,
                    FuzzDataTy dataTy) {
    if (byteArrLen == 0 and (dataTy != FUZZ_STRING or dataTy != FUZZ_WSTRING)) {
      // Do nothing
      return dst;
    }

    std::string strAsID(cStrAsID);
    strAsID = std::regex_replace(strAsID, std::regex("/"), "_");
    log_debug("ID: %s, Size: %ld, FuzzDataType: %d", strAsID.c_str(),
              byteArrLen, dataTy);

    auto consumerJsonPtr = nlohmann::ordered_json::json_pointer("/" + strAsID);
    if (consumerJson[consumerJsonPtr].is_null()) {
      // Send request to mutator that we need data for current ID
      log_error("Need mutator create data for current [%s]", strAsID.c_str());
      SendRequest({strAsID, DATA_CREATE, byteArrLen, dataTy});
      /// early leave \c leaveLLVMFuzzerTestOneInput
      leaveLLVMFuzzerTestOneInput();
    } else {
      // Already prepared data for current ID
      FuzzDataTy dataTy = consumerJson[consumerJsonPtr / "DataType"];
      log_debug("Get JSON item [%s]", strAsID.c_str());
      dumpJson(consumerJson[consumerJsonPtr]);
      switch (dataTy) {
      case FUZZ_ARRAY:
      case FUZZ_DATA:
      case FUZZ_RET: {
        std::vector<uint8_t> data =
            DecodeBase64(std::string(consumerJson[consumerJsonPtr / "Data"]));
        size_t preparedDataSize = data.size();
        if (preparedDataSize < byteArrLen) {
          size_t extraSizeNeeded = byteArrLen - preparedDataSize;
          // Send request to mutator that prepared data is not enough
          log_error("Need mutator provide more data [%ld] for current [%s]",
                    extraSizeNeeded, strAsID.c_str());
          SendRequest({strAsID, DATA_EXPAND, extraSizeNeeded, dataTy});
          leaveLLVMFuzzerTestOneInput();
        }
        if (dst == nullptr) {
          dst = (uint8_t *)malloc(byteArrLen);
          allocatedMemAreas.push_back(dst);
        }
        memcpy(dst, data.data(), byteArrLen);
        if (preparedDataSize > byteArrLen) {
          size_t sizeNeedReduced = preparedDataSize - byteArrLen;
          // Send request to mutator that prepared data is too much
          log_error("Need mutator provide less data [%d] for current [%s]",
                    strAsID.c_str());
          SendRequest({strAsID, DATA_SHRINK, sizeNeedReduced, dataTy});
        }
        break;
      }
      case FUZZ_WSTRING: {
        sgxfuzz_assert(byteArrLen == 0);
        std::vector<uint8_t> data =
            DecodeBase64(std::string(consumerJson[consumerJsonPtr / "Data"]));
        if (dst == nullptr) {
          dst = (uint8_t *)malloc(data.size());
          allocatedMemAreas.push_back(dst);
        }
        memcpy(dst, data.data(), data.size());
        sgxfuzz_assert(
            data.size() % sizeof(wchar_t) == 0 and
            (((wchar_t *)dst)[data.size() / sizeof(wchar_t) - 1] == '\0'));
        break;
      }
      case FUZZ_STRING: {
        sgxfuzz_assert(byteArrLen == 0);
        std::string data = consumerJson[consumerJsonPtr / "Data"];
        if (dst == nullptr) {
          dst = (uint8_t *)malloc(data.size() + 1);
          allocatedMemAreas.push_back(dst);
        }
        memcpy(dst, data.c_str(), data.size());
        dst[data.size()] = '\0';
        break;
      }
      case FUZZ_SIZE:
      case FUZZ_COUNT: {
        sgxfuzz_assert((byteArrLen < sizeof(size_t)));
        size_t data = consumerJson[consumerJsonPtr / "Data"];
        if (dst == nullptr) {
          dst = (uint8_t *)malloc(byteArrLen);
          allocatedMemAreas.push_back(dst);
        }
        memcpy(dst, &data, byteArrLen);
        break;
      }
      case FUZZ_BOOL: {
        sgxfuzz_assert((byteArrLen == sizeof(bool)));
        bool data = consumerJson[consumerJsonPtr / "Data"];
        if (dst == nullptr) {
          dst = (uint8_t *)malloc(sizeof(bool));
          allocatedMemAreas.push_back(dst);
        }
        *dst = data ? 1 : 0;
        break;
      }
      }
    }
    return dst;
  }

  /// @brief Encode plain byte array to base64 string
  /// @param origData A byte array
  /// @return Base64 string
  std::string EncodeBase64(std::vector<uint8_t> origData) {
    size_t encodedSize =
        boost::beast::detail::base64::encoded_size(origData.size());
    char base64CStr[encodedSize + 1];
    auto encodeResult = boost::beast::detail::base64::encode(
        base64CStr, origData.data(), origData.size());
    sgxfuzz_assert(encodeResult == encodedSize);
    base64CStr[encodedSize] = '\0';
    return std::string(base64CStr);
  }

  /// @brief Decode base64 string to plain byte array with corret size
  /// @param base64Str Base64 string
  /// @return Plain byte array with corret size
  std::vector<uint8_t> DecodeBase64(std::string base64Str) {
    size_t base64StrSize = base64Str.size();
    uint8_t byteArr[boost::beast::detail::base64::decoded_size(base64StrSize)] =
        {0};
    auto decodeResult = boost::beast::detail::base64::decode(
        byteArr, base64Str.c_str(), base64StrSize);
    return std::vector<uint8_t>(byteArr, byteArr + decodeResult.first);
  }

  size_t getUserCheckCount(char *cStrAsID) {
    std::string strAsID = std::string(cStrAsID) + "_getUserCheckCount";
    size_t result;
    getBytes(strAsID.c_str(), (uint8_t *)&result, sizeof(size_t), FUZZ_COUNT);
    return result;
  }

  bool hintSetNull(char *cStrAsID) {
    std::string strAsID = std::string(cStrAsID) + "_hintSetNull";
    bool result;
    getBytes(strAsID.c_str(), (uint8_t *)&result, sizeof(bool), FUZZ_BOOL);
    return result;
  }

  void deserializeToConsumerJson(const uint8_t *Data, size_t Size) {
    std::vector<uint8_t> bjdata(Data, Data + Size);
    try {
      consumerJson = nlohmann::ordered_json::from_bjdata(bjdata);
    } catch (ordered_json::parse_error &e) {
      // leave consumerJson empty, and it should be empty
      sgxfuzz_assert(consumerJson.empty());
    }
  }

  void clearAtConsumerEnd() {
    consumerJson.clear();
    for (auto memArea : allocatedMemAreas) {
      free(memArea);
    }
    allocatedMemAreas.clear();
  }

private:
  nlohmann::ordered_json consumerJson, mutatorJson;
  std::deque<RequestInfo> reqQueue;
  std::vector<uint8_t *> allocatedMemAreas;
};
FuzzDataFactory data_factory;

void FuzzDataFactory::dumpJson(ordered_json json) {
  log_debug_np("%s", json.dump(4).c_str());
}

void FuzzDataFactory::dumpJsonPtr(ordered_json::json_pointer ptr) {
  log_debug("%s", ptr.to_string().c_str());
}

void ShowAllECalls() {
  log_debug("[Init] Num of ECall: %d\n", sgx_fuzzer_ecall_num);
  std::string ecalls;
  for (int i = 0; i < sgx_fuzzer_ecall_num; i++) {
    ecalls += std::string(sgx_fuzzer_ecall_wrapper_name_array[i]) + "\n";
  }
  log_debug("ECalls:\n%s", ecalls.c_str());
}

// libFuzzer Callbacks
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  ShowAllECalls();
  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  return data_factory.mutate(Data, Size, MaxSize);
}
extern uint8_t __start___sancov_cntrs[];
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static int test_round = 0;
  if (test_round == 0) {
    // Round 0 of libFuzzer will feed with empty, this isn't what we want, just
    // early return
    sgxfuzz_assert(Size == 0);
    test_round++;
    return 0;
  }
  if (test_round == 1 and Size == 1 and Data[0] == '\n') {
    // Default round 1 '\n' should trigger some new feature, otherwise libFuzzer
    // will exit. And at this round we collect info to guide mutation
    __start___sancov_cntrs[0]++;
  }

  sgx_status_t ret;
  /// Deserialize data to \c FuzzDataFactory::ConsumerJSon
  data_factory.deserializeToConsumerJson(Data, Size);

  if (setjmp(sgx_fuzzer_jmp_buf) != 0) {
    /// jump from \c leaveLLVMFuzzerTestOneInput , and we leave current function
    goto exit;
  }

  // Initialize Enclave
  ret = sgx_create_enclave(ENCLAVE_FILENAME,
                           SGX_DEBUG_FLAG /* Debug Support: set to 1 */, NULL,
                           NULL, &global_eid, NULL);
  sgxfuzz_error(ret != SGX_SUCCESS, "[FAIL] Enclave initilize");

  // Test body
  for (int i = 0; i < 1 /* sgx_fuzzer_ecall_num */; i++) {
    log_debug("[TEST] ECall: %s", sgx_fuzzer_ecall_wrapper_name_array[i]);
    ret = sgx_fuzzer_ecall_array[i]();
    sgxfuzz_error(ret != SGX_SUCCESS, "[FAIL] ECall: %s",
                  sgx_fuzzer_ecall_wrapper_name_array[i]);
  }

  // Destroy Enclave
  ret = sgx_destroy_enclave(global_eid);
  sgxfuzz_error(ret != SGX_SUCCESS, "[FAIL] Enclave destroy");

exit:
  /// Clear \c FuzzDataFactory::ConsumerJSon and free temp buffer before leave
  /// current round
  data_factory.clearAtConsumerEnd();

  return 0;
}

// DriverGen Callbacks
extern "C" size_t get_count(size_t eleSize, char *cStrAsID) {
  return data_factory.getUserCheckCount(cStrAsID);
}

extern "C" uint8_t *get_bytes(size_t byteArrLen, char *cStrAsID,
                              FuzzDataTy dataType) {
  return data_factory.getBytes(cStrAsID, nullptr, byteArrLen, dataType);
}

extern "C" bool is_null_pointer(char *cStrAsID) {
  return data_factory.hintSetNull(cStrAsID);
}
