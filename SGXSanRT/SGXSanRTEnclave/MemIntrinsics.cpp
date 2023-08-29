#include "MemIntrinsics.hpp"
#include "CiphertextDetect.hpp"
#include "ErrorReport.hpp"
#include "MemAccessMgr.hpp"
#include "Poison.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanRTEnclave.hpp"
#include <assert.h>
#include <cstdlib>
#include <mbusafecrt.h>
#include <string.h>

// In order to check safe memory operations:
// If we do not instrument sgxsdk, we should replace memcpy used in memcpy_s
// with __asan_memcpy(weak symbol) by hand. (Current) Or replace memcpy_s with
// __sgxsan_memcpy_s If we need to instrument sgxsdk, we needn't extra check, as
// memcpy will be replaced with __asan_memcpy by llvm pass

#define RANGE_CHECK(beg, size, is_write, begIsInEnclave)                       \
  do {                                                                         \
    SGXSAN_ELRANGE_CHECK_BEG(beg, size)                                        \
    begIsInEnclave = true;                                                     \
    MemAccessMgrInEnclaveAccess();                                             \
    SGXSAN_ELRANGE_CHECK_MID                                                   \
    MemAccessMgrOutEnclaveAccess(beg, size, is_write, false, nullptr);         \
    SGXSAN_ELRANGE_CHECK_END;                                                  \
  } while (0);

/// \param srcSize can't be 0
#define LEAK_CHECK_MT(isSrcInEnclave, isDstInEnclave, srcAddr, srcSize)        \
  do {                                                                         \
    if (isSrcInEnclave && not isDstInEnclave) {                                \
      if (sgxsan_region_is_poisoned((uint64_t)srcAddr, srcSize,                \
                                    kL1Filter | kSGXSanSensitiveObjData)) {    \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, (uptr)srcAddr, 0, srcSize, false,       \
                           "Plaintext Transfer");                              \
      }                                                                        \
      check_output_hybrid((uint64_t)srcAddr, srcSize);                         \
    }                                                                          \
  } while (0);

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
    bool isSrcInEnclave = false, isDstInEnclave = false;

    ASAN_READ_RANGE(src, size);
    RANGE_CHECK(src, size, false, isSrcInEnclave);

    ASAN_WRITE_RANGE(dst, size);
    RANGE_CHECK(dst, size, true, isDstInEnclave);

    LEAK_CHECK_MT(isSrcInEnclave, isDstInEnclave, src, size);
  }
  return memcpy(dst, src, size);
}

void *__asan_memset(void *dst, int c, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();

    ASAN_WRITE_RANGE(dst, size);

    SGXSAN_ELRANGE_CHECK_BEG(dst, size)
    MemAccessMgrInEnclaveAccess();
    SGXSAN_ELRANGE_CHECK_MID
    MemAccessMgrOutEnclaveAccess(dst, size, true);
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

    bool isSrcInEnclave = false, isDstInEnclave = false;

    ASAN_READ_RANGE(src, size);
    RANGE_CHECK(src, size, false, isSrcInEnclave);

    ASAN_WRITE_RANGE(dst, size);
    RANGE_CHECK(dst, size, true, isDstInEnclave);

    LEAK_CHECK_MT(isSrcInEnclave, isDstInEnclave, src, size);
  }
  return memmove(dst, src, size);
}

errno_t __sgxsan_memcpy_s(void *dst, size_t dstSize, const void *src,
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

    bool isSrcInEnclave = false, isDstInEnclave = false;

    ASAN_READ_RANGE(src, count);
    RANGE_CHECK(src, count, false, isSrcInEnclave);

    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true, isDstInEnclave);

    LEAK_CHECK_MT(isSrcInEnclave, isDstInEnclave, src, count);
  }
  return memcpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_memset_s(void *dst, size_t dstSize, int c, size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();

    ASAN_WRITE_RANGE(dst, std::max(dstSize, count));

    SGXSAN_ELRANGE_CHECK_BEG(dst, std::max(dstSize, count))
    MemAccessMgrInEnclaveAccess();
    SGXSAN_ELRANGE_CHECK_MID
    MemAccessMgrOutEnclaveAccess(dst, std::max(dstSize, count), true);
    SGXSAN_ELRANGE_CHECK_END;
  }
  return memset_s(dst, dstSize, c, count);
}

int __sgxsan_memmove_s(void *dst, size_t dstSize, const void *src,
                       size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ENSURE_ASAN_INITED();

    bool isSrcInEnclave = false, isDstInEnclave = false;

    ASAN_READ_RANGE(src, count);
    RANGE_CHECK(src, count, false, isSrcInEnclave);

    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true, isDstInEnclave);

    LEAK_CHECK_MT(isSrcInEnclave, isDstInEnclave, src, count);
  }
  return memmove_s(dst, dstSize, src, count);
}