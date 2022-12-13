#include "libFuzzerCallback.h"
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
#include <regex>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using ordered_json = nlohmann::ordered_json;
namespace po = boost::program_options;

sgx_enclave_id_t global_eid = 0;
std::string ClEnclaveFileName;
size_t ClMaxStringLength;
size_t ClMaxCount;
size_t ClMaxSize;
size_t ClUserCheckSize;
int ClUsedLogLevel;
bool ClProvideNullPointer;
bool ClAlwaysMuate;
double ClProvideNullPointerProbability;
double ClReturn0Probability;

// Fuzz sequence
enum FuzzerTestModeTy { TEST_ONE, TEST_RANDOM, TEST_USER };
static std::vector<int> gFuzzerSeq;
static std::vector<int> gFilterOutIndices;
static FuzzerTestModeTy gFuzzerMode;

// From ELF
extern uint8_t __start___sancov_cntrs[];

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
  FUZZ_BOOL,
  FUZZ_SEQ,
  FUZZ_USER_CHECK_SIZE,
};

enum DataOp {
  DATA_EXPAND,
  DATA_SHRINK,
  DATA_CREATE,
  DATA_DESTROY,
};

struct RequestInfo {
  std::string StrAsParamID;
  DataOp op;
  size_t size;
  FuzzDataTy dataType;
};

struct InputJsonDataInfo {
  nlohmann::ordered_json json;
  std::vector<uint8_t> bjdata;
  std::string dataID; /* Current use SHA-1 of json content */

  void clear() {
    json.clear();
    bjdata.clear();
    dataID = "";
  }
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
    cStrBuf[size - 1] = '\0';
  }

  template <class T>
  void _insertString(ordered_json &mutatorJson,
                     ordered_json::json_pointer ptr) {
    size_t newStrLen = rand() % (ClMaxStringLength + 1);
    T newStr[newStrLen + 1];
    fillStrRand(newStr, newStrLen + 1);
    mutatorJson[ptr] = EncodeBase64(std::vector<uint8_t>(
        (uint8_t *)newStr, (uint8_t *)(newStr + newStrLen + 1)));
  }

  void insertItemInMutatorJSon(RequestInfo req) {
    auto &mutatorJson = mutatorData.json;
    nlohmann::ordered_json::json_pointer JSonPtr("/" + req.StrAsParamID);
    mutatorJson[JSonPtr / "DataType"] = req.dataType;
    switch (req.dataType) {
    case FUZZ_STRING: {
      sgxfuzz_assert(req.size == 0);
      _insertString<char>(mutatorJson, JSonPtr / "Data");
      break;
    }
    case FUZZ_WSTRING: {
      sgxfuzz_assert(req.size == 0);
      _insertString<wchar_t>(mutatorJson, JSonPtr / "Data");
      break;
    }
    case FUZZ_COUNT:
    case FUZZ_SIZE: {
      size_t maxValue = req.dataType == FUZZ_SIZE ? ClMaxSize : ClMaxCount;
      sgxfuzz_assert(req.size <= sizeof(size_t));
      size_t newData;
      fillRand(&newData, sizeof(size_t));
      newData %= (maxValue + 1);
      mutatorJson[JSonPtr / "Data"] = newData;
      break;
    }
    case FUZZ_USER_CHECK_SIZE: {
      sgxfuzz_assert(req.size <= sizeof(size_t));
      mutatorJson[JSonPtr / "Data"] = ClUserCheckSize;
      break;
    }
    case FUZZ_RET:
    case FUZZ_ARRAY:
    case FUZZ_DATA: {
      uint8_t newData[req.size];
      memset(newData, 0, req.size);
      bool return0 = (rand() % 100) < (ClReturn0Probability * 100);
      if (req.dataType == FUZZ_RET and return0) {
        // Do nothing, since already set 0
      } else {
        fillRand(newData, req.size);
      }
      mutatorJson[JSonPtr / "Data"] =
          EncodeBase64(std::vector<uint8_t>(newData, newData + req.size));
      break;
    }
    case FUZZ_BOOL: {
      int randValue = rand() % 100;
      bool result = randValue < (ClProvideNullPointerProbability * 100);
      mutatorJson[JSonPtr / "Data"] = result;
      break;
    }
    case FUZZ_SEQ: {
      ordered_json::array_t callSeq(req.size);
      // array [0,req.size)
      std::iota(callSeq.begin(), callSeq.end(), 0);
      // Fisher–Yates shuffle
      for (int i = callSeq.size() - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        std::swap(callSeq[i], callSeq[j]);
      }
      mutatorJson[JSonPtr / "Data"] = callSeq;
      break;
    }
    default: {
      abort();
      break;
    }
    }
  }

  void dump(log_level ll, ordered_json json);
  void dump(log_level ll, ordered_json::json_pointer ptr);
  void dump(log_level ll, ordered_json json, ordered_json::json_pointer ptr);

  void AdjustItemInMutatorJSon(RequestInfo req) {
    auto &mutatorJson = mutatorData.json;
    ordered_json::json_pointer JSonPtr("/" + req.StrAsParamID);
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
    switch (op) {
    case DATA_EXPAND: {
      uint8_t newData[N];
      fillRand(newData, N);
      auto adjustPt = byteArr.begin() + rand() % (byteArr.size());
      byteArr.insert(adjustPt, newData, newData + N);
      break;
    }
    case DATA_SHRINK: {
      auto adjustPt = byteArr.begin() + rand() % (byteArr.size() - N + 1);
      byteArr.erase(adjustPt, adjustPt + N);
      break;
    }
    default: {
      sgxfuzz_error(true, "[AdjustNBytes] Unsupported DATA_{Operation}");
      break;
    }
    }
  }

  template <class T>
  void _mutateString(ordered_json &mutatorJson,
                     ordered_json::json_pointer ptr) {
    auto byteArr = DecodeBase64(std::string(mutatorJson[ptr]));
    sgxfuzz_assert(byteArr.size() % sizeof(T) == 0);
    size_t strLen =
        std::min((byteArr.size() / sizeof(T)) - 1, (size_t)ClMaxStringLength);
    T str[ClMaxStringLength + 1];
    memcpy(str, byteArr.data(), strLen * sizeof(T));
    auto newRawLen = LLVMFuzzerMutate((uint8_t *)str, strLen * sizeof(T),
                                      ClMaxStringLength * sizeof(T));
    sgxfuzz_assert(newRawLen <= ClMaxStringLength * sizeof(T));
    size_t newLen = (newRawLen + sizeof(T) - 1) / sizeof(T);
    sgxfuzz_assert(newLen <= ClMaxStringLength);
    str[newLen] = '\0';
    mutatorJson[ptr] =
        EncodeBase64(std::vector<uint8_t>(str, str + newLen + 1));
  }

  void mutateOnMutatorJSon(bool canChangeSize = true) {
    auto &mutatorJson = mutatorData.json;
    for (auto pair : mutatorJson.items()) {
      if (pair.key() == "DataID")
        continue;
      ordered_json::json_pointer ptr("/" + pair.key());
      FuzzDataTy dataTy = mutatorJson[ptr / "DataType"];
      switch (dataTy) {
      case FUZZ_STRING: {
        _mutateString<char>(mutatorJson, ptr / "Data");
        break;
      }
      case FUZZ_WSTRING: {
        _mutateString<wchar_t>(mutatorJson, ptr / "Data");
        break;
      }
      case FUZZ_SIZE:
      case FUZZ_COUNT: {
        if (canChangeSize) {
          size_t maxValue = dataTy == FUZZ_SIZE ? ClMaxSize : ClMaxCount;
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
      case FUZZ_USER_CHECK_SIZE: {
        /* Do nothing */
        break;
      }
      case FUZZ_ARRAY:
      case FUZZ_DATA:
      case FUZZ_RET: {
        auto byteArr = DecodeBase64(std::string(mutatorJson[ptr / "Data"]));
        uint8_t cByteArr[byteArr.size()];
        memcpy(cByteArr, byteArr.data(), byteArr.size());
        bool return0 = (rand() % 100) < (ClReturn0Probability * 100);
        if (dataTy == FUZZ_RET and return0) {
          memset(cByteArr, 0, byteArr.size());
        } else {
          LLVMFuzzerMutate(cByteArr, byteArr.size(), byteArr.size());
        }
        // Fixed-size mutate
        mutatorJson[ptr / "Data"] = EncodeBase64(
            std::vector<uint8_t>(cByteArr, cByteArr + byteArr.size()));
        break;
      }
      case FUZZ_BOOL: {
        int randValue = rand() % 100;
        bool result = randValue < (ClProvideNullPointerProbability * 100);
        mutatorJson[ptr / "Data"] = result;
        break;
      }
      case FUZZ_SEQ: {
        ordered_json::array_t callSeq = mutatorJson[ptr / "Data"];
        // Fisher–Yates shuffle
        for (int i = callSeq.size() - 1; i > 0; i--) {
          int j = rand() % (i + 1);
          std::swap(callSeq[i], callSeq[j]);
        }
        mutatorJson[ptr / "Data"] = callSeq;
        break;
      }
      default: {
        abort();
        break;
      }
      }
    }
  }

  /// @brief Convert byte array to sha1 string
  /// @param byteArr
  /// @return
  std::string getSha1Str(std::vector<uint8_t> byteArr) {
    uint8_t hashRes[SHA_DIGEST_LENGTH] = {0};
    SHA1(byteArr.data(), byteArr.size(), hashRes);
    std::stringstream ss;
    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
      ss << std::setw(2) << std::setfill('0') << std::hex
         << (unsigned)hashRes[i];
    }
    return ss.str();
  }

  size_t mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    if (reqQueue.empty()) {
      mutatorData.bjdata = std::vector<uint8_t>(Data, Data + Size);
      try {
        mutatorData.json =
            nlohmann::ordered_json::from_bjdata(mutatorData.bjdata);
      } catch (ordered_json::parse_error &e) {
        // leave mutatorJson empty, and it should be empty
        sgxfuzz_assert(mutatorData.json.empty());
      }
      mutatorData.dataID = getSha1Str(mutatorData.bjdata);
      log_trace("[Before Mutate, ID: %s]\n", mutatorData.dataID.c_str());
      dump(LOG_LEVEL_TRACE, mutatorData.json);

      /// Arbitrarily mutate on \c mutatorJson
      mutateOnMutatorJSon();
    } else {
      // assume reqQueue is one-element queue, reason that I use queue is to
      // avoid future adjustment
      sgxfuzz_assert(reqQueue.size() == 1);
      for (auto it = reqQueue.begin(); it != reqQueue.end();) {
        mutatorData.dataID = it->first;
        DataAndReq dq = it->second;
        mutatorData.bjdata = dq.data;
        try {
          mutatorData.json =
              nlohmann::ordered_json::from_bjdata(mutatorData.bjdata);
        } catch (ordered_json::parse_error &e) {
          // leave mutatorJson empty, and it should be empty
          sgxfuzz_assert(mutatorData.json.empty());
        }
        log_trace("[Before Mutate, ID: %s]\n", mutatorData.dataID.c_str());
        dump(LOG_LEVEL_TRACE, mutatorData.json);

        // Mutate data except which is FUZZ_COUNT/FUZZ_SIZE type
        if (ClAlwaysMuate) {
          mutateOnMutatorJSon(false);
        }
        /// process \c reqQueue
        it = reqQueue.erase(it);
        log_trace("reqQueue remove %s\n", mutatorData.dataID.c_str());
        sgxfuzz_assert(reqQueue.empty());
        for (auto paramReq : dq.param2Reqs) {
          auto req = paramReq.second;
          nlohmann::ordered_json::json_pointer jsonPtr("/" + req.StrAsParamID);
          switch (req.op) {
          case DATA_CREATE: {
            sgxfuzz_assert(mutatorData.json[jsonPtr].is_null());
            insertItemInMutatorJSon(req);
            break;
          }
          case DATA_EXPAND:
          case DATA_SHRINK: {
            sgxfuzz_assert(not mutatorData.json[jsonPtr].is_null());
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
    }
    // update mutator data with new one
    mutatorData.bjdata = nlohmann::ordered_json::to_bjdata(mutatorData.json);
    mutatorData.dataID = getSha1Str(mutatorData.bjdata);
    sgxfuzz_assert(mutatorData.bjdata.size() <= MaxSize);

    memcpy(Data, mutatorData.bjdata.data(), mutatorData.bjdata.size());
    log_trace("[After Mutate, ID: %s]\n", mutatorData.dataID.c_str());
    dump(LOG_LEVEL_TRACE, mutatorData.json);
    size_t newSize = mutatorData.bjdata.size();
    mutatorData.clear();
    return newSize;
  }

  /// @brief Request to process req with mutatorJson
  /// @param bjData
  /// @param req
  void SendRequest(std::vector<uint8_t> bjData, RequestInfo req) {
    // 1. When ReadCorpus, we may send one or more requests per seed, but have
    // no opportunity to mutate in order to process request. We only keep
    // request of latest bjData.
    // 2. When test one, we may send several requests with same bjData but with
    // different paramID, record all of them
    std::string bjDataSha1 = getSha1Str(bjData);
    if (reqQueue.size() == 1) {
      if (reqQueue.begin()->first != bjDataSha1) {
        // There already is different bjData recorded
        reqQueue.clear();
      }
    } else if (reqQueue.size() > 1) {
      abort();
    }
    log_trace("reqQueue add %s %s\n", bjDataSha1.c_str(),
              req.StrAsParamID.c_str());
    DataAndReq &dq = reqQueue[bjDataSha1];
    dq.data = bjData;
    dq.param2Reqs[req.StrAsParamID] = req;
  }

  template <class T>
  void _getString(uint8_t *&dst, ordered_json &consumerJson,
                  ordered_json::json_pointer ptr) {
    std::vector<uint8_t> data = DecodeBase64(std::string(consumerJson[ptr]));
    if (dst == nullptr) {
      dst = (uint8_t *)managedMalloc(data.size());
    }
    memcpy(dst, data.data(), data.size());
    sgxfuzz_assert(data.size() % sizeof(T) == 0 and
                   (((T *)dst)[data.size() / sizeof(T) - 1] == '\0'));
  }

  /// @brief get byte array from \c ConsumerJSon, and save it to \p dst. If no
  /// byte array prepared for current \p cStrAsParamID, \c SendRequest to
  /// mutator phase
  /// @param cStrAsParamID Using JSon pointer string as ID
  /// @param dst A pre-allocated memory area, if nullptr, I will provide a valid
  /// memory area which should be destroyed at clearAtConsumerEnd() before leave
  /// LLVMFuzzerTestOneInput
  /// @param byteArrLen
  /// @param dataTy
  /// @return
  uint8_t *getBytes(const char *cStrAsParamID, uint8_t *dst, size_t byteArrLen,
                    FuzzDataTy dataTy) {
    if (byteArrLen == 0 and dataTy != FUZZ_STRING and dataTy != FUZZ_WSTRING) {
      // Do nothing
      return dst;
    }

    if (not DataGetTimes.count(cStrAsParamID)) {
      DataGetTimes[cStrAsParamID] = 0;
    }
    int times = DataGetTimes[cStrAsParamID]++;
    std::string strAsParamID =
        std::string(cStrAsParamID) + "_" + std::to_string(times);
    strAsParamID = std::regex_replace(strAsParamID, std::regex("/"), "_");

    auto consumerJsonPtr =
        nlohmann::ordered_json::json_pointer("/" + strAsParamID);
    auto &consumerJson = consumerData.json;
    if (consumerJson[consumerJsonPtr].is_null()) {
      // Send request to mutator that we need data for current ID
      SendRequest(consumerData.bjdata,
                  {strAsParamID, DATA_CREATE, byteArrLen, dataTy});
      std::stringstream ss;
      ss << "Need mutator create data for current [" << strAsParamID << "]\n";
      throw std::runtime_error(ss.str());
    } else {
      // Already prepared data for current ID
      FuzzDataTy dataTy = consumerJson[consumerJsonPtr / "DataType"];
      log_trace("Get JSON item [%s]\n", strAsParamID.c_str());
      dump(LOG_LEVEL_TRACE, consumerJson[consumerJsonPtr]);
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
          SendRequest(consumerData.bjdata,
                      {strAsParamID, DATA_EXPAND, extraSizeNeeded, dataTy});
          std::stringstream ss;
          ss << "Need mutator provide more data [" << extraSizeNeeded
             << "] for current [" << strAsParamID << "]\n";
          throw std::runtime_error(ss.str());
        }
        if (dst == nullptr) {
          dst = (uint8_t *)managedMalloc(byteArrLen);
        }
        memcpy(dst, data.data(), byteArrLen);
        if (preparedDataSize > byteArrLen) {
          size_t sizeNeedReduced = preparedDataSize - byteArrLen;
          // Send request to mutator that prepared data is too much
          log_debug("Need mutator provide less data [%d] for current [%s]\n",
                    sizeNeedReduced, strAsParamID.c_str());
          SendRequest(consumerData.bjdata,
                      {strAsParamID, DATA_SHRINK, sizeNeedReduced, dataTy});
          // we needn't early return in this situation, since we can only use
          // partial prepared data, then there may be several requests with same
          // DataID but different paramID in reqQueue
        }
        break;
      }
      case FUZZ_WSTRING: {
        sgxfuzz_assert(byteArrLen == 0);
        _getString<wchar_t>(dst, consumerJson, consumerJsonPtr / "Data");
        break;
      }
      case FUZZ_STRING: {
        sgxfuzz_assert(byteArrLen == 0);
        _getString<char>(dst, consumerJson, consumerJsonPtr / "Data");
        break;
      }
      case FUZZ_SIZE:
      case FUZZ_USER_CHECK_SIZE:
      case FUZZ_COUNT: {
        sgxfuzz_assert((byteArrLen <= sizeof(size_t)));
        size_t data = consumerJson[consumerJsonPtr / "Data"];
        if (dst == nullptr) {
          dst = (uint8_t *)managedMalloc(byteArrLen);
        }
        memcpy(dst, &data, byteArrLen);
        break;
      }
      case FUZZ_BOOL: {
        sgxfuzz_assert((byteArrLen == sizeof(bool)));
        bool data = consumerJson[consumerJsonPtr / "Data"];
        if (dst == nullptr) {
          dst = (uint8_t *)managedMalloc(sizeof(bool));
        }
        *dst = data ? 1 : 0;
        break;
      }
      default: {
        sgxfuzz_error(true, "Unsupported FUZZ_XXX type\n");
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
    if (origData.empty()) {
      return "";
    }

    size_t encodedSize = 4 * ((origData.size() + 2) / 3);
    char base64CStr[encodedSize + 1];
    size_t encodeResult = EVP_EncodeBlock((uint8_t *)base64CStr,
                                          origData.data(), origData.size());
    sgxfuzz_assert(encodedSize == encodeResult);
    base64CStr[encodedSize] = '\0';
    return std::string(base64CStr);
  }

  /// @brief Decode base64 string to plain byte array with corret size
  /// @param base64Str Base64 string
  /// @return Plain byte array with corret size
  std::vector<uint8_t> DecodeBase64(std::string base64Str) {
    if (base64Str.empty()) {
      return std::vector<uint8_t>();
    }

    size_t base64StrSize = base64Str.size();
    size_t decodedSize = 3 * base64StrSize / 4;
    uint8_t byteArr[decodedSize + 1];
    size_t decodeResult =
        EVP_DecodeBlock(byteArr, (uint8_t *)base64Str.c_str(), base64StrSize);
    sgxfuzz_assert(decodedSize == decodeResult);
    size_t equalSignCnt = 0;
    for (size_t i = base64StrSize; i > 0; i--) {
      if (base64Str[i - 1] == '=') {
        equalSignCnt++;
      } else {
        break;
      }
    }
    sgxfuzz_assert(equalSignCnt <= 2);
    return std::vector<uint8_t>(byteArr, byteArr + decodeResult - equalSignCnt);
  }

  size_t getUserCheckCount(char *cStrAsParamID) {
    std::string strAsParamID =
        std::string(cStrAsParamID) + "_getUserCheckCount";
    size_t result;
    getBytes(strAsParamID.c_str(), (uint8_t *)&result, sizeof(size_t),
             FUZZ_USER_CHECK_SIZE);
    return result;
  }

  bool hintSetNull(char *cStrAsParamID) {
    std::string strAsParamID = std::string(cStrAsParamID) + "_hintSetNull";
    bool result;
    getBytes(strAsParamID.c_str(), (uint8_t *)&result, sizeof(bool), FUZZ_BOOL);
    return result;
  }

  void deserializeToConsumerJson(const uint8_t *Data, size_t Size) {
    consumerData.bjdata = std::vector<uint8_t>(Data, Data + Size);
    try {
      consumerData.json =
          nlohmann::ordered_json::from_bjdata(consumerData.bjdata);
    } catch (ordered_json::parse_error &e) {
      // leave consumerJson empty, and it should be empty
      sgxfuzz_assert(consumerData.json.empty());
    }
    consumerData.dataID = getSha1Str(consumerData.bjdata);
    log_debug("[Before Test, ID: %s]\n", consumerData.dataID.c_str());
    dump(LOG_LEVEL_TRACE, consumerData.json);
  }

  void clearAtConsumerEnd() {
    consumerData.clear();
    for (auto memArea : allocatedMemAreas) {
      // log_debug("free %p\n", memArea);
      free(memArea);
    }
    allocatedMemAreas.clear();
    DataGetTimes.clear();
  }

  void *managedMalloc(size_t size) {
    void *ptr = malloc(size);
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

  char *jsonID(char *parentID, char *currentID, char *appendID) {
    sgxfuzz_assert(parentID and currentID);
    std::string fullID = std::string(parentID) + "/" + std::string(currentID) +
                         (appendID ? ("/" + std::string(appendID)) : "");
    return managedStr2CStr(fullID);
  }

  char *getInstanceID(char *origID, unsigned long instanceIdx) {
    auto instanceID = std::string(origID) + "-" + std::to_string(instanceIdx);
    return managedStr2CStr(instanceID);
  }

  std::vector<int> getCallSequence(size_t funcNum) {
    auto &consumerJson = consumerData.json;
    if (consumerJson["CallSeq"].is_null()) {
      SendRequest(consumerData.bjdata,
                  {"CallSeq", DATA_CREATE, funcNum, FUZZ_SEQ});
      throw std::runtime_error("Need Call Sequence Data");
    } else {
      ordered_json::array_t callSeq = consumerJson["CallSeq"]["Data"];
      std::vector<int> intCallSeq;
      for (auto seq : callSeq) {
        intCallSeq.push_back((int)seq);
      }
      return intCallSeq;
    }
  }

private:
  InputJsonDataInfo consumerData, mutatorData;
  struct DataAndReq {
    std::vector<uint8_t> data;
    std::map<std::string /* ParamID */, RequestInfo> param2Reqs;
  };
  std::map<std::string /* DataID */, DataAndReq> reqQueue;
  std::vector<uint8_t *> allocatedMemAreas;
  std::unordered_map<std::string, size_t> DataGetTimes;
};
FuzzDataFactory data_factory;

void FuzzDataFactory::dump(log_level ll, ordered_json json) {
  if (ll > ClUsedLogLevel)
    return;
  sgxfuzz_log(ll, false, "%s\n", json.dump(4).c_str());
}

void FuzzDataFactory::dump(log_level ll, ordered_json::json_pointer ptr) {
  if (ll > ClUsedLogLevel)
    return;
  sgxfuzz_log(ll, true, "%s\n", ptr.to_string().c_str());
}

void FuzzDataFactory::dump(log_level ll, ordered_json json,
                           ordered_json::json_pointer jsonPtr) {
  if (ll > ClUsedLogLevel)
    return;
  sgxfuzz_log(ll, false, "%s\n%s\n", jsonPtr.to_string().c_str(),
              json[jsonPtr].dump(4));
}

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
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  std::map<std::string, int> wrapperName2Idx;
  for (int i = 0; i < sgx_fuzzer_ecall_num; i++) {
    wrapperName2Idx[sgx_fuzzer_ecall_wrapper_name_array[i]] = i;
  }

  // default mode is random
  gFuzzerMode = TEST_RANDOM;

  // Declare the supported options.
  po::options_description desc("LibFuzzerCallback's inner options");
  desc.add_options()("inner_help", "produce help message")(
      "cb_enclave_file_name",
      po::value<std::string>(&ClEnclaveFileName)
          ->default_value("enclave.signed.so"),
      "Name of target Enclave file")(
      "cb_max_count", po::value<size_t>(&ClMaxCount)->default_value(32),
      "Max count of elements for pointer which size is unknown or not fixed")(
      "cb_max_size", po::value<size_t>(&ClMaxSize)->default_value(128),
      "Max size of pointer element")(
      "cb_max_str_len",
      po::value<size_t>(&ClMaxStringLength)->default_value(128),
      "Max length of string")("cb_filter_out", po::value<std::string>(),
                              "Specified ECalls that we don't test")(
      "sgxfuzz_print_ecalls", "show all ecalls valid in this Enclave")(
      "sgxfuzz_test_one", po::value<int>(), "test only one API user specified")(
      "sgxfuzz_test_user", po::value<std::vector<std::string>>()->multitoken(),
      "test a number of APIs user specified")(
      "cb_log_level", po::value<int>(&ClUsedLogLevel)->default_value(2),
      "0-Always, 1-Error, 2-Warning(Default), 3-Debug, 4-Trace")(
      "cb_provide_nullptr",
      po::value<bool>(&ClProvideNullPointer)->default_value(true),
      "Provide NULL for fuzzed pointer parameter")(
      "cb_always_mutate", po::value<bool>(&ClAlwaysMuate)->default_value(false),
      "We will directly goto mutation stage when lack of params, and at the "
      "mutation stage, whether we mutate params already exist (but don't "
      "mutate params used to indicate size/count)")(
      "cb_provide_nullptr_probability",
      po::value<double>(&ClProvideNullPointerProbability)->default_value(0.01),
      "The minimum granularity is 0.01 (1%)")(
      "cb_user_check_size",
      po::value<size_t>(&ClUserCheckSize)->default_value(4096),
      "Specify prepared data size for user_check pointer")(
      "cb_return0_probability",
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
  if (vm.count("inner_help")) {
    std::stringstream ss;
    ss << desc << "\n";
    log_always(ss.str().c_str());
    exit(0);
  } else if (vm.count("sgxfuzz_test_one")) {
    gFuzzerMode = TEST_ONE;
    gFuzzerSeq.push_back(vm["sgxfuzz_test_one"].as<int>());
    log_always("Test one: %d\n", gFuzzerSeq[0]);
  } else if (vm.count("sgxfuzz_test_user")) {
    gFuzzerMode = TEST_USER;
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
  } else if (vm.count("sgxfuzz_print_ecalls")) {
    ShowAllECalls();
    exit(0);
  }

  if (vm.count("cb_filter_out")) {
    std::string fiterOutECalls = vm["cb_filter_out"].as<std::string>();
    std::vector<std::string> fiterOutECallVec;
    boost::split(fiterOutECallVec, fiterOutECalls,
                 [](char c) { return c == ','; });
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
  ShowAllECalls();
  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  return data_factory.mutate(Data, Size, MaxSize);
}

extern "C" void LLVMFuzzerEarlyAfterRunOne() {
  // Destroy Enclave
  sgxfuzz_error(sgx_destroy_enclave(global_eid) != SGX_SUCCESS,
                "[FAIL] Enclave destroy");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static int test_round = 0;
  if (test_round == 0 && Size == 0) {
    // 1. Fuzz from empty: Round 0 of libFuzzer will feed with empty (Size ==
    // 0, e.g. ./app), this isn't what we want, just early return
    // 2. Fuzz with specified input (e.g. ./app crash-xxx), then we shouldn't
    // early return
    test_round++;
    return 0;
  }
  if (test_round == 1 and Size == 1 and Data[0] == '\n') {
    // Default round 1 '\n' should trigger some new feature, otherwise libFuzzer
    // will exit. And at this round we collect info to guide mutation
    __start___sancov_cntrs[0]++;
  }

  sgx_status_t ret;
  static size_t emitTimes = 0, fullSucceedTimes = 0, succeedTimes = 0;
  bool hasTest = false;
  std::vector<int> callSeq;
  /// Deserialize data to \c FuzzDataFactory::ConsumerJSon
  data_factory.deserializeToConsumerJson(Data, Size);

  emitTimes++;
  // Initialize Enclave
  ret = sgx_create_enclave(ClEnclaveFileName.c_str(),
                           SGX_DEBUG_FLAG /* Debug Support: set to 1 */, NULL,
                           NULL, &global_eid, NULL);
  sgxfuzz_error(ret != SGX_SUCCESS, "[FAIL] Enclave initilize");

  // Test body
  if (gFuzzerMode == TEST_ONE || gFuzzerMode == TEST_USER) {
    callSeq = gFuzzerSeq;
  } else {
    try {
      callSeq = data_factory.getCallSequence(sgx_fuzzer_ecall_num);
    } catch (std::runtime_error const &e) {
      log_debug("%s\n", e.what());
      goto exit;
    }
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
    try {
      ret = sgx_fuzzer_ecall_array[i]();
    } catch (std::runtime_error const &e) {
      log_debug("%s\n", e.what());
      goto exit;
    }
    sgxfuzz_error(ret != SGX_SUCCESS and ret != SGX_ERROR_INVALID_PARAMETER and
                      ret != SGX_ERROR_ECALL_NOT_ALLOWED,
                  "[FAIL] ECall: %s", sgx_fuzzer_ecall_wrapper_name_array[i]);
    hasTest = true;
  }
  fullSucceedTimes++;

exit:
  /// Clear \c FuzzDataFactory::ConsumerJSon and free temp buffer before leave
  /// current round
  data_factory.clearAtConsumerEnd();
  if (hasTest)
    succeedTimes++;
  log_debug("FullSucceedTimes/SucceedTimes/EmitTimes=%ld/%ld/%ld\n",
            fullSucceedTimes, succeedTimes, emitTimes);
  return 0;
}

// DriverGen Callbacks
extern "C" size_t get_count(size_t eleSize, char *cStrAsParamID) {
  return data_factory.getUserCheckCount(cStrAsParamID);
}

extern "C" uint8_t *get_bytes(size_t byteArrLen, char *cStrAsParamID,
                              FuzzDataTy dataType) {
  return data_factory.getBytes(cStrAsParamID, nullptr, byteArrLen, dataType);
}

extern "C" bool is_null_pointer(char *cStrAsParamID) {
  return ClProvideNullPointer ? data_factory.hintSetNull(cStrAsParamID) : false;
}

extern "C" char *DFJoinID(char *parentID, char *currentID, char *appendID) {
  return data_factory.jsonID(parentID, currentID, appendID);
}

extern "C" char *DFGetInstanceID(char *origID, unsigned long i) {
  return data_factory.getInstanceID(origID, i);
}

extern "C" void *DFManagedMalloc(size_t size) {
  return data_factory.managedMalloc(size);
}
