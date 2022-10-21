#include "MemIntrinsics.hpp"
#include "CiphertextDetect.hpp"
#include "ErrorReport.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanDefs.h"
#include "SGXSanLog.hpp"
#include "SGXSanRTEnclave.hpp"
#include "WhitelistCheck.hpp"
#include <assert.h>
#include <cstdlib>
#include <mbusafecrt.h>
#include <string.h>

// In order to check safe memory operations:
// If we do not instrument sgxsdk, we should replace memcpy used in memcpy_s
// with __asan_memcpy(weak symbol) by hand. (Current) Or replace memcpy_s with
// sgxsan_memcpy_s If we need to instrument sgxsdk, we needn't extra check, as
// memcpy will be replaced with __asan_memcpy by llvm pass

void *__asan_memcpy(void *dst, const void *src, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, size, (const char *)src, size),
          "[%s] %p:%lu overlap with %p:%lu\n", "memcpy", dst, size, src, size);
    }
    bool isSrcInEnclave = false;
    SGXSAN_ELRANGE_CHECK_BEG(src, size)
    ASAN_READ_RANGE(src, size);
    isSrcInEnclave = true;
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQueryEx(src, size, false, false, nullptr);
    SGXSAN_ELRANGE_CHECK_END;

    SGXSAN_ELRANGE_CHECK_BEG(dst, size)
    ASAN_WRITE_RANGE(dst, size);
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQuery(dst, size);
    if (isSrcInEnclave) {
      SGXSAN_WARNING_DETAIL(
          sgxsan_region_is_poisoned_filtered((uint64_t)src, size,
                                             0x8F | kSGXSanSensitiveObjData),
          "Plaintext Transfer", (uint64_t)src, size);
      check_output_hybrid((uint64_t)src, size);
    }
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memcpy(dst, src, size);
}

void *__asan_memset(void *dst, int c, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();
    SGXSAN_ELRANGE_CHECK_BEG(dst, size)
    ASAN_WRITE_RANGE(dst, size);
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQuery(dst, size);
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memset(dst, c, size);
}

void *__asan_memmove(void *dst, const void *src, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();
    bool isSrcInEnclave = false;
    SGXSAN_ELRANGE_CHECK_BEG(src, size)
    ASAN_READ_RANGE(src, size);
    isSrcInEnclave = true;
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQueryEx(src, size, false, false, nullptr);
    SGXSAN_ELRANGE_CHECK_END;

    SGXSAN_ELRANGE_CHECK_BEG(dst, size)
    ASAN_WRITE_RANGE(dst, size);
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQuery(dst, size);
    if (isSrcInEnclave) {
      SGXSAN_WARNING_DETAIL(
          sgxsan_region_is_poisoned_filtered((uint64_t)src, size,
                                             0x8F | kSGXSanSensitiveObjData),
          "Plaintext Transfer", (uint64_t)src, size);
      check_output_hybrid((uint64_t)src, size);
    }
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memmove(dst, src, size);
}

errno_t sgxsan_memcpy_s(void *dst, size_t dstSize, const void *src,
                        size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, dstSize, (const char *)src, count),
          "[%s] %p:%lu overlap with %p:%lu\n", "memcpy_s", dst, dstSize, src,
          count);
    }
    bool isSrcInEnclave = false;
    SGXSAN_ELRANGE_CHECK_BEG(src, count)
    ASAN_READ_RANGE(src, count);
    isSrcInEnclave = true;
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQueryEx(src, count, false, false, nullptr);
    SGXSAN_ELRANGE_CHECK_END;

    SGXSAN_ELRANGE_CHECK_BEG(dst, dstSize)
    ASAN_WRITE_RANGE(dst, dstSize);
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQuery(dst, dstSize);
    if (isSrcInEnclave) {
      SGXSAN_WARNING_DETAIL(
          sgxsan_region_is_poisoned_filtered((uint64_t)src, count,
                                             0x8F | kSGXSanSensitiveObjData),
          "Plaintext Transfer", (uint64_t)src, count);
      check_output_hybrid((uint64_t)src, count);
    }
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memcpy_s(dst, dstSize, src, count);
}

errno_t sgxsan_memset_s(void *dst, size_t dstSize, int c, size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();
    SGXSAN_ELRANGE_CHECK_BEG(dst, dstSize > count ? dstSize : count)
    ASAN_WRITE_RANGE(dst, dstSize > count ? dstSize : count);
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQuery(dst, dstSize > count ? dstSize : count);
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memset_s(dst, dstSize, c, count);
}

int sgxsan_memmove_s(void *dst, size_t sizeInBytes, const void *src,
                     size_t count) {
  if (sizeInBytes == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();
    bool isSrcInEnclave = false;
    SGXSAN_ELRANGE_CHECK_BEG(src, count)
    ASAN_READ_RANGE(src, count);
    isSrcInEnclave = true;
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQueryEx(src, count, false, false, nullptr);
    SGXSAN_ELRANGE_CHECK_END;

    SGXSAN_ELRANGE_CHECK_BEG(dst, sizeInBytes)
    ASAN_WRITE_RANGE(dst, sizeInBytes);
    SGXSAN_ELRANGE_CHECK_MID
    WhitelistQuery(dst, sizeInBytes);
    if (isSrcInEnclave) {
      SGXSAN_WARNING_DETAIL(
          sgxsan_region_is_poisoned_filtered((uint64_t)src, count,
                                             0x8F | kSGXSanSensitiveObjData),
          "Plaintext Transfer", (uint64_t)src, count);
      check_output_hybrid((uint64_t)src, count);
    }
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memmove_s(dst, sizeInBytes, src, count);
}