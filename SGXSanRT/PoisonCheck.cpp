#include "PoisonCheck.h"
#include "OutAddrWhitelist.h"
#include "Poison.h"
#include <algorithm>
#include <assert.h>
#include <string.h>
#include <tuple>

// -------------------------- Run-time entry ------------------- {{{1
// exported functions
// error report
#define ASAN_REPORT_ERROR(type, is_write, size)                                \
  extern "C"                                                                   \
      __attribute__((noinline)) void __asan_report_##type##size(uptr addr) {   \
    GET_CALLER_PC_BP_SP;                                                       \
    ReportGenericError(pc, bp, sp, addr, is_write, size, true);                \
  }

ASAN_REPORT_ERROR(load, false, 1)
ASAN_REPORT_ERROR(load, false, 2)
ASAN_REPORT_ERROR(load, false, 4)
ASAN_REPORT_ERROR(load, false, 8)
ASAN_REPORT_ERROR(load, false, 16)
ASAN_REPORT_ERROR(store, true, 1)
ASAN_REPORT_ERROR(store, true, 2)
ASAN_REPORT_ERROR(store, true, 4)
ASAN_REPORT_ERROR(store, true, 8)
ASAN_REPORT_ERROR(store, true, 16)

#define ASAN_REPORT_ERROR_N(type, is_write)                                    \
  extern "C" __attribute__((noinline)) void __asan_report_##type##_n(          \
      uptr addr, uptr size) {                                                  \
    GET_CALLER_PC_BP_SP;                                                       \
    ReportGenericError(pc, bp, sp, addr, is_write, size, true);                \
  }

ASAN_REPORT_ERROR_N(load, false)
ASAN_REPORT_ERROR_N(store, true)

// memory access callback
#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                      \
  extern "C" __attribute__((noinline)) void __asan_##type##size(               \
      uptr addr, bool toCmp, char *funcName, bool atBridge) {                  \
    uptr shadowMapPtr = MEM_TO_SHADOW(addr), shadowByte, inEnclaveFlag;        \
    if (size <= SHADOW_GRANULARITY) {                                          \
      shadowByte = *(uint8_t *)shadowMapPtr;                                   \
      inEnclaveFlag = kSGXSanInEnclaveMagic;                                   \
    } else {                                                                   \
      shadowByte = *(uint16_t *)shadowMapPtr;                                  \
      inEnclaveFlag = (kSGXSanInEnclaveMagic << 8) + kSGXSanInEnclaveMagic;    \
    }                                                                          \
    if (UNLIKELY(shadowByte != inEnclaveFlag)) {                               \
      if (LIKELY(shadowByte & inEnclaveFlag)) {                                \
        uptr filter = size <= SHADOW_GRANULARITY                               \
                          ? kL1Filter                                          \
                          : ((kL1Filter << 8) + kL1Filter);                    \
        shadowByte &= filter;                                                  \
        if (UNLIKELY(shadowByte)) {                                            \
          if (UNLIKELY(size >= SHADOW_GRANULARITY ||                           \
                       (int8_t)((addr & (SHADOW_GRANULARITY - 1)) + size -     \
                                1) >= (int8_t)shadowByte)) {                   \
            GET_CALLER_PC_BP_SP;                                               \
            ReportGenericError(pc, bp, sp, addr, is_write, size, true);        \
          }                                                                    \
        }                                                                      \
      } else if (not atBridge) {                                               \
        WhitelistQuery((void *)addr, size, is_write, toCmp, funcName);         \
      }                                                                        \
    }                                                                          \
  }

ASAN_MEMORY_ACCESS_CALLBACK(load, false, 1)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 2)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 4)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 8)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 16)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 1)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 2)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 4)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 8)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 16)

#define ASAN_MEMORY_ACCESS_CALLBACK_N(type, is_write)                          \
  extern "C" __attribute__((noinline)) void __asan_##type##N(                  \
      uptr addr, uptr size, bool toCmp, char *funcName, bool atBridge) {       \
    InOutEnclaveStatus addrInOutEnclaveStatus;                                 \
    uptr addrPoisonStatus;                                                     \
    std::tie(addrInOutEnclaveStatus, addrPoisonStatus) =                       \
        RegionInOutEnclaveStatusAndPoisonStatus(addr, size);                   \
    if (addrInOutEnclaveStatus == InEnclave) {                                 \
      if (addrPoisonStatus) {                                                  \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);            \
      }                                                                        \
    } else if (not atBridge) {                                                 \
      WhitelistQuery((void *)addr, size, is_write, toCmp, funcName);           \
    }                                                                          \
  }

ASAN_MEMORY_ACCESS_CALLBACK_N(load, false)
ASAN_MEMORY_ACCESS_CALLBACK_N(store, true)

std::pair<InOutEnclaveStatus, PoisonStatus>
AddressInOutEnclaveStatusAndPoisonStatus(uptr addr, uint8_t filter) {
  int8_t shadow_value = *(int8_t *)MEM_TO_SHADOW(addr);
  if (LIKELY(shadow_value == kSGXSanInEnclaveMagic)) {
    // early found just in Enclave, filter is needn't to use
    return std::pair<InOutEnclaveStatus, PoisonStatus>(InEnclave, NotPoisoned);
  } else if (UNLIKELY((shadow_value & kSGXSanInEnclaveMagic) == 0)) {
    // find it outside enclave
    return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                       UnknownPoisonStatus);
  } else {
    shadow_value &= filter;
    if (LIKELY(shadow_value == 0)) {
      return std::pair<InOutEnclaveStatus, PoisonStatus>(InEnclave,
                                                         NotPoisoned);
    } else {
      // current know it must in Enclave
      int8_t L2Bits = L2F(shadow_value);
      if (L2Bits) {
        return std::pair<InOutEnclaveStatus, PoisonStatus>(InEnclave,
                                                           IsPoisoned);
      }
      int8_t L1Bits = L1F(shadow_value);
      // last_accessed_byte should <= SHADOW_GRANULARITY - 1 (i.e. 0x7)
      uint8_t last_accessed_byte = addr & (SHADOW_GRANULARITY - 1);
      return std::pair<InOutEnclaveStatus, PoisonStatus>(
          InEnclave, last_accessed_byte >= L1Bits ? IsPoisoned : NotPoisoned);
    }
  }
}

std::pair<InOutEnclaveStatus, PoisonStatus>
FastRegionInOutEnclaveStatusAndPoisonStatus(uptr beg, uptr size) {
  if (beg == 0) {
    return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                       UnknownPoisonStatus);
  }
  if (size == 0)
    return std::pair<InOutEnclaveStatus, PoisonStatus>(
        UnknownInOutEnclaveStatus, UnknownPoisonStatus);
  InOutEnclaveStatus InOutEnclaveStatus_0_4, InOutEnclaveStatus_1_4,
      InOutEnclaveStatus_2_4, InOutEnclaveStatus_3_4, InOutEnclaveStatus_4_4;
  PoisonStatus PoisonStatus_0_4, PoisonStatus_1_4, PoisonStatus_2_4,
      PoisonStatus_3_4, PoisonStatus_4_4;
  std::tie(InOutEnclaveStatus_0_4, PoisonStatus_0_4) =
      AddressInOutEnclaveStatusAndPoisonStatus(beg, kL1Filter);
  std::tie(InOutEnclaveStatus_2_4, PoisonStatus_2_4) =
      AddressInOutEnclaveStatusAndPoisonStatus(beg + size / 2, kL1Filter);
  std::tie(InOutEnclaveStatus_4_4, PoisonStatus_4_4) =
      AddressInOutEnclaveStatusAndPoisonStatus(beg + size - 1, kL1Filter);
  // make sure all is at same side
  sgxsan_error(InOutEnclaveStatus_0_4 != InOutEnclaveStatus_2_4 or
                   InOutEnclaveStatus_2_4 != InOutEnclaveStatus_4_4,
               "Not at same side\n");
  if (size <= 32) {
    if (InOutEnclaveStatus_0_4 == InEnclave) {
      // in enclave
      return std::pair<InOutEnclaveStatus, PoisonStatus>(
          InEnclave, PoisonStatus_0_4 or PoisonStatus_2_4 or PoisonStatus_4_4
                         ? IsPoisoned
                         : NotPoisoned);
    } else {
      // out enclave
      return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                         UnknownPoisonStatus);
    }
  } else if (size <= 64) {
    std::tie(InOutEnclaveStatus_1_4, PoisonStatus_1_4) =
        AddressInOutEnclaveStatusAndPoisonStatus(beg + size / 4, kL1Filter);
    std::tie(InOutEnclaveStatus_3_4, PoisonStatus_3_4) =
        AddressInOutEnclaveStatusAndPoisonStatus(beg + 3 * size / 4, kL1Filter);
    sgxsan_error(InOutEnclaveStatus_0_4 != InOutEnclaveStatus_1_4 or
                     InOutEnclaveStatus_1_4 != InOutEnclaveStatus_3_4,
                 "Not at same side\n");
    if (InOutEnclaveStatus_0_4 == InEnclave) {
      // in enclave
      return std::pair<InOutEnclaveStatus, PoisonStatus>(
          InEnclave, PoisonStatus_0_4 or PoisonStatus_1_4 or PoisonStatus_2_4 or
                             PoisonStatus_3_4 or PoisonStatus_4_4
                         ? IsPoisoned
                         : NotPoisoned);
    } else {
      // out enclave
      return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                         UnknownPoisonStatus);
    }
  }
  return std::pair<InOutEnclaveStatus, PoisonStatus>(UnknownInOutEnclaveStatus,
                                                     UnknownPoisonStatus);
}

std::pair<InOutEnclaveStatus, PoisonStatus>
RegionInOutEnclaveStatusAndStrictPoisonStatus(uint8_t *beg, uptr size,
                                               uint8_t filter) {
  if (beg == nullptr)
    return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                       UnknownPoisonStatus);
  sgxsan_assert(0 < size and size <= (1ULL << 40)); // Sanity check
  uint8_t *end = beg + size;                        // offset by 1
  uptr *aligned_beg = (uptr *)RoundUpTo((uptr)beg, sizeof(uptr));
  uptr *aligned_end =
      (uptr *)RoundDownTo((uptr)end, sizeof(uptr)); // offset by 1
  uptr allBitOr = 0, allBitAnd = ~0;
  uint8_t *allBitAndI8 = (uint8_t *)&allBitAnd;
  bool extendedFlag = false;
  // Prologue.
  for (uint8_t *mem = beg; mem < (uint8_t *)aligned_beg && mem < end; mem++) {
    allBitOr |= *mem;
    *allBitAndI8 &= *mem;
  }
  // Aligned loop.
  if (aligned_beg < aligned_end) {
    extendedFlag = true;
  }
  for (; aligned_beg < aligned_end; aligned_beg++) {
    allBitOr |= *aligned_beg;
    allBitAnd &= *aligned_beg;
  }
  // Epilogue.
  if ((uint8_t *)aligned_end >= beg) {
    for (uint8_t *mem = (uint8_t *)aligned_end; mem < end; mem++) {
      allBitOr |= *mem;
      *allBitAndI8 &= *mem;
    }
  }
  if (extendedFlag) {
    // focus on all uptr bits
    uptr extendedInEnclaveFlag = ExtendInt8(kSGXSanInEnclaveMagic);
    uptr allBitOrFilterInEnclaveFlag = allBitOr & extendedInEnclaveFlag;
    sgxsan_error(allBitOrFilterInEnclaveFlag !=
                     (allBitAnd & extendedInEnclaveFlag),
                 "Partial is poisoned while others are unpoisoned\n");
    if (allBitOr == extendedInEnclaveFlag) {
      // found just in Enclave, don't need filter
      return std::pair<InOutEnclaveStatus, PoisonStatus>(InEnclave,
                                                         NotPoisoned);
    } else if (allBitOrFilterInEnclaveFlag == 0) {
      // just outside Enclave
      return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                         UnknownPoisonStatus);
    } else {
      sgxsan_assert(allBitOrFilterInEnclaveFlag == extendedInEnclaveFlag);
      return std::pair<InOutEnclaveStatus, PoisonStatus>(
          InEnclave, allBitOr & ExtendInt8(filter) ? IsPoisoned : NotPoisoned);
    }
  } else {
    // focus on 8 bits
    sgxsan_assert((allBitOr & ~0xFF) == 0);
    uptr allBitOrFilterInEnclaveFlag = allBitOr & kSGXSanInEnclaveMagic;
    sgxsan_error(allBitOrFilterInEnclaveFlag !=
                     (*allBitAndI8 & kSGXSanInEnclaveMagic),
                 "Partial is poisoned while others are unpoisoned\n");
    if (allBitOr == kSGXSanInEnclaveMagic) {
      return std::pair<InOutEnclaveStatus, PoisonStatus>(InEnclave,
                                                         NotPoisoned);
    } else if (allBitOrFilterInEnclaveFlag == 0) {
      return std::pair<InOutEnclaveStatus, PoisonStatus>(OutEnclave,
                                                         UnknownPoisonStatus);
    } else {
      sgxsan_assert(allBitOrFilterInEnclaveFlag == kSGXSanInEnclaveMagic);
      return std::pair<InOutEnclaveStatus, PoisonStatus>(
          InEnclave, allBitOr & filter ? IsPoisoned : NotPoisoned);
    }
  }
}

std::pair<InOutEnclaveStatus, uptr>
RegionInOutEnclaveStatusAndPoisonStatus(uptr beg, uptr size, uint8_t filter,
                                        bool need_poisoned_addr) {
  if (!beg)
    return std::pair<InOutEnclaveStatus, uptr>(OutEnclave, beg);
  sgxsan_assert(size);
  uptr end = beg + size; // offset by one
  // A offset-by-one bug in original ASan?
  sgxsan_assert(beg < end and AddrIsInMem(beg) and AddrIsInMem(end - 1));

  InOutEnclaveStatus regionInOutEnclaveStatus, begInOutEnclaveStatus,
      endInOutEnclaveStatus, alignedRegionInOutEnclaveStatus;
  PoisonStatus regionPoisonStatus, begPoisonStatus, endPoisonStatus,
      alignedRegionPoisonStatus;
  if (filter == kL1Filter) {
    std::tie(regionInOutEnclaveStatus, regionPoisonStatus) =
        FastRegionInOutEnclaveStatusAndPoisonStatus(beg, size);
  } else {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
  }
  if (regionInOutEnclaveStatus == InEnclave) {
    if (not regionPoisonStatus) {
      return std::pair<InOutEnclaveStatus, uptr>(InEnclave, 0);
    }
  } else if (regionInOutEnclaveStatus == OutEnclave) {
    return std::pair<InOutEnclaveStatus, uptr>(OutEnclave, 0);
  } else {
    // UnknownInOutEnclaveStatus returned by Fast method
    uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
    uptr aligned_e = RoundDownTo(end - 1, SHADOW_GRANULARITY);
    uptr shadow_beg = MemToShadow(aligned_b);
    uptr shadow_end = MemToShadow(aligned_e);

    // First check the first and the last application bytes,
    // then check the SHADOW_GRANULARITY-aligned region
    std::tie(begInOutEnclaveStatus, begPoisonStatus) =
        AddressInOutEnclaveStatusAndPoisonStatus(beg, filter);
    std::tie(endInOutEnclaveStatus, endPoisonStatus) =
        AddressInOutEnclaveStatusAndPoisonStatus(end - 1, filter);
    // make sure all bytes at same side
    sgxsan_error(begInOutEnclaveStatus != endInOutEnclaveStatus,
                 "Partial is poisoned while others are unpoisoned\n");
    if (not begInOutEnclaveStatus or not(begPoisonStatus or endPoisonStatus)) {
      // 1) out enclave
      // 2) in enclave, but beg & end is not poisoned
      if (shadow_end <= shadow_beg) {
        // already check each ShadowByte
        return std::pair<InOutEnclaveStatus, uptr>(begInOutEnclaveStatus, 0);
      } else {
        // need to check granuality-aligned shadow value
        std::tie(alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus) =
            RegionInOutEnclaveStatusAndStrictPoisonStatus(
                (uint8_t *)shadow_beg, shadow_end - shadow_beg, filter);
        // make sure all bytes at same side
        sgxsan_error(begInOutEnclaveStatus != alignedRegionInOutEnclaveStatus,
                     "Partial is poisoned while others are unpoisoned\n");
        if (begInOutEnclaveStatus == OutEnclave) {
          // out enclave
          return std::pair<InOutEnclaveStatus, uptr>(OutEnclave, 0);
        } else if (not alignedRegionPoisonStatus) {
          // in enclave, each byte is not poisoned
          return std::pair<InOutEnclaveStatus, uptr>(InEnclave, 0);
        }
      }
    }
  }
  // must be poisoned
  if (need_poisoned_addr) {
    // The fast check failed, so we have a poisoned byte somewhere.
    // Find it slowly.
    for (; beg < end; beg++) {
      std::tie(begInOutEnclaveStatus, begPoisonStatus) =
          AddressInOutEnclaveStatusAndPoisonStatus(beg, filter);
      sgxsan_assert(begInOutEnclaveStatus == InEnclave);
      if (begPoisonStatus) {
        return std::pair<InOutEnclaveStatus, uptr>(InEnclave, beg);
      }
    }
    sgxsan_error(true, "there must be a poisoned byte\n");
  } else {
    return std::pair<InOutEnclaveStatus, uptr>(InEnclave, 1);
  }
}

bool RegionIsInEnclaveAndPoisoned(uptr beg, uptr size, uint8_t filter) {
  sgxsan_assert(beg && size);
  InOutEnclaveStatus begInOutEnclaveStatus;
  uptr begPoisonStatus;
  std::tie(begInOutEnclaveStatus, begPoisonStatus) =
      RegionInOutEnclaveStatusAndPoisonStatus(beg, size, filter);
  return begInOutEnclaveStatus == InEnclave && begPoisonStatus;
}

int sgx_is_within_enclave(const void *addr, size_t size) {
  InOutEnclaveStatus status;
  std::tie(status, std::ignore) =
      RegionInOutEnclaveStatusAndPoisonStatus((uptr)addr, size);
  if (status == InEnclave)
    return 1;
  else if (status == OutEnclave)
    return 0;
  else
    abort();
}

int sgx_is_outside_enclave(const void *addr, size_t size) {
  InOutEnclaveStatus status;
  std::tie(status, std::ignore) =
      RegionInOutEnclaveStatusAndPoisonStatus((uptr)addr, size);
  if (status == InEnclave)
    return 0;
  else if (status == OutEnclave)
    return 1;
  else
    abort();
}

#define RANGE_CHECK(beg, size, InOutEnclaveStatus, PoisonedAddr, IsWrite)      \
  do {                                                                         \
    std::tie(InOutEnclaveStatus, PoisonedAddr) =                               \
        RegionInOutEnclaveStatusAndPoisonStatus((uptr)beg, size, kL1Filter,    \
                                                true);                         \
    if (InOutEnclaveStatus == InEnclave) {                                     \
      if (PoisonedAddr) {                                                      \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, PoisonedAddr, IsWrite, size, true);     \
      }                                                                        \
    } else {                                                                   \
      WhitelistQuery(beg, size, IsWrite);                                      \
    }                                                                          \
  } while (0);

#define LEAK_CHECK_MT(srcInOutEnclave, dstInOutEnclave, srcAddr, srcSize)      \
  do {                                                                         \
    if (srcInOutEnclave == InEnclave && dstInOutEnclave == OutEnclave) {       \
      if (RegionInOutEnclaveStatusAndPoisonStatus((uptr)srcAddr, srcSize,      \
                                                  kL2Filter)                   \
              .second) {                                                       \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, (uptr)srcAddr, 0, srcSize, false,       \
                           "Plaintext Transfer");                              \
      }                                                                        \
      check_output_hybrid((uptr)srcAddr, srcSize);                             \
    }                                                                          \
  } while (0);

extern "C" {
/// Memory Intrinsics Callback
void *__asan_memcpy(void *dst, const void *src, uptr size) {
  if (LIKELY(asan_inited)) {
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, size, (const char *)src, size),
          "%p:%lu overlap with %p:%lu\n", dst, size, src, size);
    }
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, size, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    LEAK_CHECK_MT(srcInOutEnclaveStatus, dstInOutEnclaveStatus, src, size);
  }
  return memcpy(dst, src, size);
}

void *__asan_memset(void *dst, int c, uptr size) {
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memset(dst, c, size);
}

void *__asan_memmove(void *dst, const void *src, uptr size) {
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, size, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    LEAK_CHECK_MT(srcInOutEnclaveStatus, dstInOutEnclaveStatus, src, size);
  }
  return memmove(dst, src, size);
}

typedef error_t errno_t;
extern errno_t memcpy_s(void *dst, size_t sizeInBytes, const void *src,
                        size_t count);
extern errno_t memmove_s(void *dst, size_t sizeInBytes, const void *src,
                         size_t count);
extern errno_t memset_s(void *s, size_t smax, int c, size_t n);

errno_t __sgxsan_memcpy_s(void *dst, size_t dstSize, const void *src,
                          size_t count) {
  if (LIKELY(asan_inited)) {
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, dstSize, (const char *)src, count),
          "[%s] %p:%lu overlap with %p:%lu\n", "memcpy_s", dst, dstSize, src,
          count);
    }
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, count, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    LEAK_CHECK_MT(srcInOutEnclaveStatus, dstInOutEnclaveStatus, src, count);
  }
  return memcpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_memset_s(void *dst, size_t dstSize, int c, size_t n) {
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, std::max(dstSize, n), dstInOutEnclaveStatus,
                dstPoisonedAddr, true);
  }
  return memset_s(dst, dstSize, c, n);
}

errno_t __sgxsan_memmove_s(void *dst, size_t dstSize, const void *src,
                           size_t count) {
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, count, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    LEAK_CHECK_MT(srcInOutEnclaveStatus, dstInOutEnclaveStatus, src, count);
  }
  return memmove_s(dst, dstSize, src, count);
}

/// Bridge Check
void SGXSanBridgeCheck(void *ptr, uint64_t size, int cnt) {
  sgxsan_assert(size > 0 && cnt != 0);
  uint64_t min_size = size * std::max(1, cnt);
  sgxsan_assert(min_size >= size);
  InOutEnclaveStatus ptrInOutEnclaveStatus;
  uptr ptrPoisonStatus;
  std::tie(ptrInOutEnclaveStatus, ptrPoisonStatus) =
      RegionInOutEnclaveStatusAndPoisonStatus((uptr)ptr, min_size,
                                              kSGXSanSensitiveLayout);
  if (ptrInOutEnclaveStatus == InEnclave) {
    if (ptrPoisonStatus) {
      GET_CALLER_PC_BP_SP;
      ReportGenericError(pc, bp, sp, (uptr)ptr, 0, min_size, false);
    }
  } else {
    WhitelistAdd(ptr, (cnt == -1) ? (1 << 10) : (size * cnt));
  }
}
}
