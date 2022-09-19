#pragma once

#include "Poison.h"
#include "SGXSanRT.h"
#include <stdint.h>
#include <utility>

enum InOutEnclaveStatus {
  UnknownInOutEnclaveStatus = -1,
  OutEnclave = 0,
  InEnclave = 1,
  RangeMixedInOutEnclave = 2,
  RangeOverflow = 3,
  RangeInvalid = 4,
};
enum PoisonStatus { UnknownPoisonStatus = -1, NotPoisoned = 0, IsPoisoned = 1 };

/// @brief Check only one shadow byte, this function don't call other check.
/// @param addr Address used to check shadow byte
/// @param[out] addrInOutEnclaveStatus Returns InEnclave or OutEnclave.
/// @param[out] addrPoisonStatus If addrInOutEnclaveStatus is InEnclave, return
/// NotPoisoned or IsPoisoned. If addrInOutEnclaveStatus is OutEnclave, returns
/// UnknownPoisonStatus.
/// @param filter Tell which bits in one byte is interesting
void AddressInOutEnclaveStatusAndPoisonStatus(
    uptr addr, InOutEnclaveStatus &addrInOutEnclaveStatus,
    PoisonStatus &addrPoisonStatus, uint8_t filter = kL1Filter);

/// @brief Only check level 1 bits. We assume that a redzone is at least 16
/// bytes.
/// @param beg Range begin
/// @param size Range size
/// @param[out] regionInOutEnclaveStatus Return UnknownInOutEnclaveStatus if
/// size is 0 or size is too large(>64) since we can't quickly decide. Return
/// RangeOverflow if beg+size cause int overflow. Return RangeMixedInOutEnclave
/// if not all address in or out Enclave. Otherwise return InEnclave or
/// OutEnclave.
/// @param[out] regionPoisonStatus When regionInOutEnclaveStatus is InEnclave,
/// return IsPoisoned if we can quickly decide that the region is unpoisoned,
/// otherwise NotPoisoned. When regionInOutEnclaveStatus is others, return
/// UnknownPoisonStatus.
void FastRegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus);

/// @brief Tell us whether region is poisoned, even if it's partial poisoned
/// (what 'Strict' means), this function don't call other check.
/// @param beg Begin of shadow region
/// @param size Size of shadow region
/// @param[out] regionInOutEnclaveStatus Return UnknownInOutEnclaveStatus if
/// size is 0. Return RangeOverflow if size > 2^40. Return
/// RangeMixedInOutEnclave if partial shadow bytes indicate InEnclave while
/// others indicate OutEnclave. Otherwise return InEnclave or OutEnclave
/// @param[out] regionPoisonStatus
/// If regionInOutEnclaveStatus returns InEnclave, return IsPoisoned or
/// NotPoisoned, otherwise return UnknownPoisonStatus.
/// @param filter Tell which bits in one byte is interesting
void ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
    uint8_t *beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus, uint8_t filter = kL1Filter);

/// @brief Tell us whether region is poisoned, partial poisoned will be checked
/// @param beg Begin of region
/// @param size Size of region
/// @param[out] regionInOutEnclaveStatus Return RangeOverflow when (beg + size)
/// cause int overflow. Return RangeInvalid if region isn't in valid memory.
/// Return RangeMixedInOutEnclave if partial shadow bytes indicate InEnclave
/// while others indicate OutEnclave. Otherwise return InEnclave or OutEnclave.
/// @param[out] regionPoisonStatus If regionInOutEnclaveStatus returns
/// InEnclave, return NotPoisoned or IsPoisoned
/// @param filter Tell which bits in one byte is interesting
void RegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus, uint8_t filter = kL1Filter);

/// @brief Tell us whether region is poisoned and the first address are
/// poisoned, partial poisoned will be checked
/// @param beg Begin of region
/// @param size Size of region
/// @param[out] regionInOutEnclaveStatus Return RangeOverflow when (beg + size)
/// cause int overflow. Return RangeInvalid if region isn't in valid memory.
/// Return RangeMixedInOutEnclave if partial shadow bytes indicate InEnclave
/// while others indicate OutEnclave. Otherwise return InEnclave or OutEnclave.
/// @param[out] regionFirstPoisonedAddr If regionInOutEnclaveStatus returns
/// InEnclave, return first poisoned address
/// @param filter Tell which bits in one byte is interesting
void RegionInOutEnclaveStatusAndPoisonedAddr(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    uptr &regionFirstPoisonedAddr, uint8_t filter = kL1Filter);

#if defined(__cplusplus)
extern "C" {
#endif
/// @brief Tell whether beg is InEnclave & Poisoned
/// @param beg
/// @param size
/// @param filter
/// @return Return true only when beg is InEnclave & Poisoned
bool RegionIsInEnclaveAndPoisoned(uptr beg, uptr size, uint8_t filter);

int sgx_is_within_enclave(const void *addr, size_t size);
int sgx_is_outside_enclave(const void *addr, size_t size);
#if defined(__cplusplus)
}
#endif
