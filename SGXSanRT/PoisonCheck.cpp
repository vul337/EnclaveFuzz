#include "PoisonCheck.h"
#include "MemAccessMgr.h"
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
      uptr addr, bool toCmp, char *funcName) {                                 \
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
        MemAccessMgrInEnclaveAccess();                                         \
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
      } else {                                                                 \
        MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, toCmp,      \
                                     funcName);                                \
      }                                                                        \
    } else {                                                                   \
      MemAccessMgrInEnclaveAccess();                                           \
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
      uptr addr, uptr size, bool toCmp, char *funcName) {                      \
    InOutEnclaveStatus addrInOutEnclaveStatus;                                 \
    PoisonStatus addrPoisonStatus;                                             \
    RegionInOutEnclaveStatusAndPoisonStatus(                                   \
        addr, size, addrInOutEnclaveStatus, addrPoisonStatus);                 \
    if (addrInOutEnclaveStatus == InEnclave) {                                 \
      MemAccessMgrInEnclaveAccess();                                           \
      if (addrPoisonStatus != NotPoisoned) {                                   \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);            \
      }                                                                        \
    } else if (addrInOutEnclaveStatus == OutEnclave) {                         \
      MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, toCmp,        \
                                   funcName);                                  \
    } else {                                                                   \
      sgxsan_error(true, "Invalid addrInOutEnclaveStatus\n");                  \
    }                                                                          \
  }

ASAN_MEMORY_ACCESS_CALLBACK_N(load, false)
ASAN_MEMORY_ACCESS_CALLBACK_N(store, true)

void AddressInOutEnclaveStatusAndPoisonStatus(
    uptr addr, InOutEnclaveStatus &addrInOutEnclaveStatus,
    PoisonStatus &addrPoisonStatus, uint8_t filter) {
  int8_t shadow_value = *(int8_t *)MEM_TO_SHADOW(addr);
  if (LIKELY(shadow_value == kSGXSanInEnclaveMagic)) {
    // early found just in Enclave, filter is needn't to use
    addrInOutEnclaveStatus = InEnclave;
    addrPoisonStatus = NotPoisoned;
  } else if (UNLIKELY((shadow_value & kSGXSanInEnclaveMagic) == 0)) {
    // find it outside enclave
    addrInOutEnclaveStatus = OutEnclave;
    addrPoisonStatus = UnknownPoisonStatus;
  } else {
    shadow_value &= filter;
    // current know it must in Enclave
    addrInOutEnclaveStatus = InEnclave;
    if (LIKELY(shadow_value == 0)) {
      addrPoisonStatus = NotPoisoned;
    } else {
      int8_t L2Bits = L2F(shadow_value);
      if (L2Bits) {
        addrPoisonStatus = IsPoisoned;
      } else {
        int8_t L1Bits = L1F(shadow_value);
        // last_accessed_byte should <= SHADOW_GRANULARITY - 1 (i.e. 0x7)
        uint8_t last_accessed_byte = addr & (SHADOW_GRANULARITY - 1);
        addrPoisonStatus =
            last_accessed_byte >= L1Bits ? IsPoisoned : NotPoisoned;
      }
    }
  }
}

void FastRegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus) {
  if (beg == 0) {
    regionInOutEnclaveStatus = OutEnclave;
    regionPoisonStatus = UnknownPoisonStatus;
  } else if (size == 0 or size > 64) {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
    regionPoisonStatus = UnknownPoisonStatus;
  } else if (beg + size < beg) {
    regionInOutEnclaveStatus = RangeOverflow;
    regionPoisonStatus = UnknownPoisonStatus;
  } else {
    InOutEnclaveStatus InOutEnclaveStatus_0_4, InOutEnclaveStatus_1_4,
        InOutEnclaveStatus_2_4, InOutEnclaveStatus_3_4, InOutEnclaveStatus_4_4;
    PoisonStatus PoisonStatus_0_4, PoisonStatus_1_4, PoisonStatus_2_4,
        PoisonStatus_3_4, PoisonStatus_4_4;
    AddressInOutEnclaveStatusAndPoisonStatus(beg, InOutEnclaveStatus_0_4,
                                             PoisonStatus_0_4);
    AddressInOutEnclaveStatusAndPoisonStatus(
        beg + size / 2, InOutEnclaveStatus_2_4, PoisonStatus_2_4);
    AddressInOutEnclaveStatusAndPoisonStatus(
        beg + size - 1, InOutEnclaveStatus_4_4, PoisonStatus_4_4);
    // make sure all is at same side
    if (InOutEnclaveStatus_0_4 != InOutEnclaveStatus_2_4 or
        InOutEnclaveStatus_2_4 != InOutEnclaveStatus_4_4) {
      regionInOutEnclaveStatus = RangeMixedInOutEnclave;
      regionPoisonStatus = UnknownPoisonStatus;
    } else if (size <= 32) {
      if (InOutEnclaveStatus_0_4 /* Pick anyone */ == InEnclave) {
        // in enclave
        regionInOutEnclaveStatus = InEnclave;
        regionPoisonStatus =
            PoisonStatus_0_4 or PoisonStatus_2_4 or PoisonStatus_4_4
                ? IsPoisoned
                : NotPoisoned;
      } else if (InOutEnclaveStatus_0_4 /* Pick anyone */ == OutEnclave) {
        // out enclave
        regionInOutEnclaveStatus = OutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else {
        abort();
      }
    } else if (size <= 64) {
      AddressInOutEnclaveStatusAndPoisonStatus(
          beg + size / 4, InOutEnclaveStatus_1_4, PoisonStatus_1_4);
      AddressInOutEnclaveStatusAndPoisonStatus(
          beg + 3 * size / 4, InOutEnclaveStatus_3_4, PoisonStatus_3_4);
      if (InOutEnclaveStatus_0_4 != InOutEnclaveStatus_1_4 or
          InOutEnclaveStatus_1_4 != InOutEnclaveStatus_3_4) {
        regionInOutEnclaveStatus = RangeMixedInOutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else if (InOutEnclaveStatus_0_4 /* Pick anyone */ == InEnclave) {
        // in enclave
        regionInOutEnclaveStatus = InEnclave;
        regionPoisonStatus = PoisonStatus_0_4 or PoisonStatus_1_4 or
                                     PoisonStatus_2_4 or PoisonStatus_3_4 or
                                     PoisonStatus_4_4
                                 ? IsPoisoned
                                 : NotPoisoned;
      } else if (InOutEnclaveStatus_0_4 /* Pick anyone */ == OutEnclave) {
        // out enclave
        regionInOutEnclaveStatus = OutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else {
        abort();
      }
    } else {
      abort();
    }
  }
}

void ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
    uint8_t *beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus, uint8_t filter) {
  // beg is nullptr when ShadowMap start from 0?
  if (size == 0) {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
    regionPoisonStatus = UnknownPoisonStatus;
  } else if (size > (1ULL << 40)) {
    // Sanity check
    regionInOutEnclaveStatus = RangeOverflow;
    regionPoisonStatus = UnknownPoisonStatus;
  } else {
    uint8_t *end = beg + size; // offset by 1
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
      if (allBitOrFilterInEnclaveFlag != (allBitAnd & extendedInEnclaveFlag)) {
        regionInOutEnclaveStatus = RangeMixedInOutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else if (allBitOr == extendedInEnclaveFlag) {
        // found just in Enclave, don't need filter
        regionInOutEnclaveStatus = InEnclave;
        regionPoisonStatus = NotPoisoned;
      } else if (allBitOrFilterInEnclaveFlag == 0) {
        // just outside Enclave
        regionInOutEnclaveStatus = OutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else {
        sgxsan_assert(allBitOrFilterInEnclaveFlag == extendedInEnclaveFlag);
        regionInOutEnclaveStatus = InEnclave;
        regionPoisonStatus =
            allBitOr & ExtendInt8(filter) ? IsPoisoned : NotPoisoned;
      }
    } else {
      // focus on 8 bits
      sgxsan_assert((allBitOr & ~0xFF) == 0);
      uptr allBitOrFilterInEnclaveFlag = allBitOr & kSGXSanInEnclaveMagic;
      if (allBitOrFilterInEnclaveFlag !=
          (*allBitAndI8 & kSGXSanInEnclaveMagic)) {
        regionInOutEnclaveStatus = RangeMixedInOutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else if (allBitOr == kSGXSanInEnclaveMagic) {
        regionInOutEnclaveStatus = InEnclave;
        regionPoisonStatus = NotPoisoned;
      } else if (allBitOrFilterInEnclaveFlag == 0) {
        regionInOutEnclaveStatus = OutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else {
        sgxsan_assert(allBitOrFilterInEnclaveFlag == kSGXSanInEnclaveMagic);
        regionInOutEnclaveStatus = InEnclave;
        regionPoisonStatus = allBitOr & filter ? IsPoisoned : NotPoisoned;
      }
    }
  }
}

void RegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus, uint8_t filter) {
  // Early error
  if (beg == 0) {
    regionInOutEnclaveStatus = OutEnclave;
    regionPoisonStatus = UnknownPoisonStatus;
  } else if (size == 0) {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
    regionPoisonStatus = UnknownPoisonStatus;
  } else {
    uptr end =
        beg + size; // Offset by one. A offset-by-one bug in original ASan?
    if (beg > end) {
      regionInOutEnclaveStatus = RangeOverflow;
      regionPoisonStatus = UnknownPoisonStatus;
    } else if (not(AddrIsInMem(beg) and AddrIsInMem(end - 1))) {
      regionInOutEnclaveStatus = RangeInvalid;
      regionPoisonStatus = UnknownPoisonStatus;
    } else {
      InOutEnclaveStatus begInOutEnclaveStatus, endInOutEnclaveStatus,
          alignedRegionInOutEnclaveStatus;
      PoisonStatus begPoisonStatus, endPoisonStatus, alignedRegionPoisonStatus;

      if (filter == kL1Filter and size <= 64) {
        /// Quick check
        FastRegionInOutEnclaveStatusAndPoisonStatus(
            beg, size, regionInOutEnclaveStatus, regionPoisonStatus);
      } else {
        /// Full check
        uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
        uptr aligned_e = RoundDownTo(end - 1, SHADOW_GRANULARITY);
        uptr shadow_beg = MemToShadow(aligned_b);
        uptr shadow_end = MemToShadow(aligned_e);

        // First check the first and the last application bytes,
        // then check the SHADOW_GRANULARITY-aligned region
        AddressInOutEnclaveStatusAndPoisonStatus(beg, begInOutEnclaveStatus,
                                                 begPoisonStatus, filter);
        AddressInOutEnclaveStatusAndPoisonStatus(end - 1, endInOutEnclaveStatus,
                                                 endPoisonStatus, filter);
        // make sure all bytes at same side
        if (begInOutEnclaveStatus != endInOutEnclaveStatus) {
          regionInOutEnclaveStatus = RangeMixedInOutEnclave;
          regionPoisonStatus = UnknownPoisonStatus;
        } else if (begInOutEnclaveStatus == OutEnclave) {
          // out enclave
          regionInOutEnclaveStatus = OutEnclave;
          regionPoisonStatus = UnknownPoisonStatus;
          if (shadow_end > shadow_beg) {
            // need to check granuality-aligned shadow value
            ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
                (uint8_t *)shadow_beg, shadow_end - shadow_beg,
                alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus,
                filter);
            // make sure all bytes at same side
            if (alignedRegionInOutEnclaveStatus != OutEnclave or
                alignedRegionInOutEnclaveStatus == RangeMixedInOutEnclave) {
              regionInOutEnclaveStatus = RangeMixedInOutEnclave;
            }
          } else {
            // already check each ShadowByte
            // do nothing
          }
        } else if (begInOutEnclaveStatus == InEnclave) {
          if (shadow_end <= shadow_beg) {
            // already check each ShadowByte
            regionInOutEnclaveStatus = InEnclave;
            regionPoisonStatus = (begPoisonStatus == NotPoisoned and
                                  endPoisonStatus == NotPoisoned)
                                     ? NotPoisoned
                                     : IsPoisoned;
          } else {
            // need to check granuality-aligned shadow value
            ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
                (uint8_t *)shadow_beg, shadow_end - shadow_beg,
                alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus,
                filter);
            // make sure all bytes at same side
            if (InEnclave != alignedRegionInOutEnclaveStatus or
                alignedRegionInOutEnclaveStatus == RangeMixedInOutEnclave) {
              regionInOutEnclaveStatus = RangeMixedInOutEnclave;
              regionPoisonStatus = UnknownPoisonStatus;
            } else {
              regionInOutEnclaveStatus = InEnclave;
              regionPoisonStatus = (begPoisonStatus == NotPoisoned and
                                    endPoisonStatus == NotPoisoned and
                                    alignedRegionPoisonStatus == NotPoisoned)
                                       ? NotPoisoned
                                       : IsPoisoned;
            }
          }
        } else {
          abort();
        }
      }
    }
  }
}

void RegionInOutEnclaveStatusAndPoisonedAddr(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    uptr &regionFirstPoisonedAddr, uint8_t filter) {
  if (beg == 0) {
    regionInOutEnclaveStatus = OutEnclave;
  } else if (size == 0) {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
  } else {
    uptr end = beg + size;
    if (beg > end) {
      regionInOutEnclaveStatus = RangeOverflow;
    } else if (not AddrIsInMem(beg) or not AddrIsInMem(end - 1)) {
      regionInOutEnclaveStatus = RangeInvalid;
    } else {
      InOutEnclaveStatus begInOutEnclaveStatus, endInOutEnclaveStatus,
          alignedRegionInOutEnclaveStatus;
      PoisonStatus begPoisonStatus, endPoisonStatus, alignedRegionPoisonStatus;

      if (filter == kL1Filter and size <= 64) {
        /// Quick check
        PoisonStatus regionPoisonStatus;
        FastRegionInOutEnclaveStatusAndPoisonStatus(
            beg, size, regionInOutEnclaveStatus, regionPoisonStatus);
        regionFirstPoisonedAddr = regionPoisonStatus;
      } else {
        /// Full check
        uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
        uptr aligned_e = RoundDownTo(end - 1, SHADOW_GRANULARITY);
        uptr shadow_beg = MemToShadow(aligned_b);
        uptr shadow_end = MemToShadow(aligned_e);

        // First check the first and the last application bytes,
        // then check the SHADOW_GRANULARITY-aligned region
        AddressInOutEnclaveStatusAndPoisonStatus(beg, begInOutEnclaveStatus,
                                                 begPoisonStatus, filter);
        AddressInOutEnclaveStatusAndPoisonStatus(end - 1, endInOutEnclaveStatus,
                                                 endPoisonStatus, filter);
        // make sure all bytes at same side
        if (begInOutEnclaveStatus != endInOutEnclaveStatus) {
          regionInOutEnclaveStatus = RangeMixedInOutEnclave;
        } else if (begInOutEnclaveStatus == OutEnclave) {
          // out enclave
          regionInOutEnclaveStatus = OutEnclave;
          if (shadow_end > shadow_beg) {
            // need to check granuality-aligned shadow value
            ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
                (uint8_t *)shadow_beg, shadow_end - shadow_beg,
                alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus,
                filter);
            // make sure all bytes at same side
            if (alignedRegionInOutEnclaveStatus != OutEnclave or
                alignedRegionInOutEnclaveStatus == RangeMixedInOutEnclave) {
              regionInOutEnclaveStatus = RangeMixedInOutEnclave;
            }
          } else {
            // already check each ShadowByte
            // do nothing
          }
        } else if (begInOutEnclaveStatus == InEnclave) {
          if (shadow_end <= shadow_beg) {
            // already check each ShadowByte
            regionInOutEnclaveStatus = InEnclave;
            regionFirstPoisonedAddr = (begPoisonStatus == NotPoisoned and
                                       endPoisonStatus == NotPoisoned)
                                          ? NotPoisoned
                                          : IsPoisoned;
          } else {
            // need to check granuality-aligned shadow value
            ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
                (uint8_t *)shadow_beg, shadow_end - shadow_beg,
                alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus,
                filter);
            // make sure all bytes at same side
            if (InEnclave != alignedRegionInOutEnclaveStatus or
                alignedRegionInOutEnclaveStatus == RangeMixedInOutEnclave) {
              regionInOutEnclaveStatus = RangeMixedInOutEnclave;
            } else {
              regionInOutEnclaveStatus = InEnclave;
              regionFirstPoisonedAddr =
                  (begPoisonStatus == NotPoisoned and
                   endPoisonStatus == NotPoisoned and
                   alignedRegionPoisonStatus == NotPoisoned)
                      ? NotPoisoned
                      : IsPoisoned;
            }
          }
        } else {
          abort();
        }
      }
      if (regionInOutEnclaveStatus == InEnclave and
          regionFirstPoisonedAddr == IsPoisoned) {
        // must be poisoned
        // The fast check failed, so we have a poisoned byte somewhere.
        // Find it slowly.
        for (; beg < end; beg++) {
          AddressInOutEnclaveStatusAndPoisonStatus(beg, begInOutEnclaveStatus,
                                                   begPoisonStatus, filter);
          sgxsan_assert(begInOutEnclaveStatus == InEnclave);
          if (begPoisonStatus == IsPoisoned) {
            regionFirstPoisonedAddr = beg;
            return;
          }
        }
        sgxsan_error(true, "there must be a poisoned byte\n");
      }
    }
  }
}

bool RegionIsInEnclaveAndPoisoned(uptr beg, uptr size, uint8_t filter) {
  if (beg == 0 or size == 0) {
    return false;
  } else {
    uptr end = beg + size;
    if (beg > end or not AddrIsInMem(beg) or not AddrIsInMem(end - 1)) {
      return false;
    } else {
      InOutEnclaveStatus regionInOutEnclaveStatus, begInOutEnclaveStatus,
          endInOutEnclaveStatus, alignedRegionInOutEnclaveStatus;
      PoisonStatus regionPoisonStatus, begPoisonStatus, endPoisonStatus,
          alignedRegionPoisonStatus;

      if (filter == kL1Filter and size <= 64) {
        /// Quick check
        FastRegionInOutEnclaveStatusAndPoisonStatus(
            beg, size, regionInOutEnclaveStatus, regionPoisonStatus);
        return regionInOutEnclaveStatus == InEnclave and
               regionPoisonStatus == IsPoisoned;
      } else {
        /// Full check
        uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
        uptr aligned_e = RoundDownTo(end - 1, SHADOW_GRANULARITY);
        uptr shadow_beg = MemToShadow(aligned_b);
        uptr shadow_end = MemToShadow(aligned_e);

        // First check the first and the last application bytes,
        // then check the SHADOW_GRANULARITY-aligned region
        AddressInOutEnclaveStatusAndPoisonStatus(beg, begInOutEnclaveStatus,
                                                 begPoisonStatus, filter);
        AddressInOutEnclaveStatusAndPoisonStatus(end - 1, endInOutEnclaveStatus,
                                                 endPoisonStatus, filter);
        // make sure all bytes at same side
        if (begInOutEnclaveStatus != endInOutEnclaveStatus) {
          return false;
        } else if (begInOutEnclaveStatus == OutEnclave) {
          // out enclave
          return false;
        } else if (begInOutEnclaveStatus == InEnclave) {
          if (shadow_end <= shadow_beg) {
            // already check each ShadowByte
            return not begPoisonStatus == NotPoisoned or
                   not endPoisonStatus == NotPoisoned;
          } else {
            // need to check granuality-aligned shadow value
            ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
                (uint8_t *)shadow_beg, shadow_end - shadow_beg,
                alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus,
                filter);
            // make sure all bytes at same side
            if (InEnclave != alignedRegionInOutEnclaveStatus or
                alignedRegionInOutEnclaveStatus == RangeMixedInOutEnclave) {
              return false;
            } else {
              return not(begPoisonStatus == NotPoisoned and
                         endPoisonStatus == NotPoisoned and
                         alignedRegionPoisonStatus == NotPoisoned);
            }
          }
        } else {
          abort();
        }
      }
    }
  }
}

int sgx_is_within_enclave(const void *addr, size_t size) {
  if (size == 0) {
    // Note: If size is zero, check one byte
    size = 1;
  }
  InOutEnclaveStatus addrInOutEnclaveStatus;
  PoisonStatus addrPoisonStatus;
  RegionInOutEnclaveStatusAndPoisonStatus(
      (uptr)addr, size, addrInOutEnclaveStatus, addrPoisonStatus);
  if (addrInOutEnclaveStatus == InEnclave)
    return 1;
  else
    return 0;
}

int sgx_is_outside_enclave(const void *addr, size_t size) {
  if (size == 0) {
    // Note: If size is zero, check one byte
    size = 1;
  }
  InOutEnclaveStatus addrInOutEnclaveStatus;
  PoisonStatus addrPoisonStatus;
  RegionInOutEnclaveStatusAndPoisonStatus(
      (uptr)addr, size, addrInOutEnclaveStatus, addrPoisonStatus);
  if (addrInOutEnclaveStatus == OutEnclave)
    return 1;
  else
    return 0;
}

/// \param size should not be 0
#define RANGE_CHECK(beg, size, regionInOutEnclaveStatus, PoisonedAddr,         \
                    IsWrite)                                                   \
  do {                                                                         \
    RegionInOutEnclaveStatusAndPoisonedAddr(                                   \
        (uptr)beg, size, regionInOutEnclaveStatus, PoisonedAddr, kL1Filter);   \
    if (regionInOutEnclaveStatus == InEnclave) {                               \
      MemAccessMgrInEnclaveAccess();                                           \
      if (PoisonedAddr) {                                                      \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, PoisonedAddr, IsWrite, size, true);     \
      }                                                                        \
    } else if (regionInOutEnclaveStatus == OutEnclave) {                       \
      MemAccessMgrOutEnclaveAccess(beg, size, IsWrite);                        \
    } else {                                                                   \
      sgxsan_error(true, "Invalid regionInOutEnclaveStatus\n");                \
    }                                                                          \
  } while (0);

/// \param srcSize can't be 0
#define LEAK_CHECK_MT(srcInOutEnclave, dstInOutEnclave, srcAddr, srcSize)      \
  do {                                                                         \
    if (srcInOutEnclave == InEnclave && dstInOutEnclave == OutEnclave) {       \
      InOutEnclaveStatus _srcInOutEnclave;                                     \
      PoisonStatus _srcPoisonedStatus;                                         \
      RegionInOutEnclaveStatusAndPoisonStatus((uptr)srcAddr, srcSize,          \
                                              _srcInOutEnclave,                \
                                              _srcPoisonedStatus, kL2Filter);  \
      sgxsan_assert(_srcInOutEnclave == InEnclave);                            \
      if (_srcPoisonedStatus != NotPoisoned) {                                 \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, (uptr)srcAddr, 0, srcSize, false,       \
                           "[WARNING] Plaintext Transfer");                    \
      }                                                                        \
      check_output_hybrid((uptr)srcAddr, srcSize);                             \
    }                                                                          \
  } while (0);

extern "C" {
/// Memory Intrinsics Callback
void *__asan_memcpy(void *dst, const void *src, uptr size) {
  if (size == 0)
    return dst;
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
  if (size == 0)
    return dst;
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memset(dst, c, size);
}

void *__asan_memmove(void *dst, const void *src, uptr size) {
  if (size == 0)
    return dst;
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
  if (dstSize == 0 or count == 0)
    return 0;
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
  if (dstSize == 0 or n == 0)
    return 0;
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
  if (dstSize == 0 or count == 0)
    return 0;
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, count, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    LEAK_CHECK_MT(srcInOutEnclaveStatus, dstInOutEnclaveStatus, src, count);
  }
  return memmove_s(dst, dstSize, src, count);
}
}
