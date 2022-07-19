#pragma once

#include "Poison.h"
#include "SGXSanRT.h"
#include <stdint.h>
#include <utility>

enum InOutEnclaveStatus {
  UnknownInOutEnclaveStatus = -1,
  OutEnclave = 0,
  InEnclave = 1
};
enum PoisonStatus { UnknownPoisonStatus = -1, NotPoisoned = 0, IsPoisoned = 1 };

/// \param[out] addrInOutEnclaveStatus
/// Never returns \c Unknown.
/// \param[out] addrPoisonStatus
/// 1. If \p addrInOutEnclaveStatus returns \c InEnclave, never \c Unknown.
/// 2. If \p addrInOutEnclaveStatus returns \c OutEnclave, returns \c Unknown.
void AddressInOutEnclaveStatusAndPoisonStatus(
    uptr addr, InOutEnclaveStatus &addrInOutEnclaveStatus,
    PoisonStatus &addrPoisonStatus, uint8_t filter = kL1Filter);

/// \brief Only check level 1 bits
/// \param[out] regionInOutEnclaveStatus
/// If \p size is too large(>64), may return \c UnknownInOutEnclaveStatus
/// \param[out] regionPoisonStatus
/// When \p regionInOutEnclaveStatus is \c InEnclave, return \c IsPoisoned if we
/// can quickly decide that the region is unpoisoned, otherwise \c NotPoisoned.
/// We assume that a redzone is at least 16 bytes.
void FastRegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus);

/// \brief Tell us whether region is poisoned, even if it's partial poisoned
/// (what 'Strict' means)
/// \param[out] regionInOutEnclaveStatus
/// Never returns \c Unknown
/// \param[out] regionPoisonStatus
/// 1. If \p regionInOutEnclaveStatus returns \c InEnclave, never \c Unknown.
/// 2. If \p regionInOutEnclaveStatus returns \c OutEnclave, return \c Unknown.
void RegionInOutEnclaveStatusAndStrictPoisonStatus(
    uint8_t *beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus, uint8_t filter = kL1Filter);

/// \brief Tell us whether region is poisoned, partial poisoned will be checked
/// \param[in] size Can't be 0
/// \param[out] regionInOutEnclaveStatus
/// Never returns \c Unknown
/// \param[out] regionPoisonStatus
/// 1. If \p regionInOutEnclaveStatus returns \c InEnclave, returns
/// \c NotPoisoned or poisoned address
/// (when \p need_poisoned_addr is true)
/// 2. If \p regionInOutEnclaveStatus returns \c OutEnclave, no meaning
/// \param[in] need_poisoned_addr If we needn't get poisoned address, this
/// function run faster
void RegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus, uint8_t filter = kL1Filter);
void RegionInOutEnclaveStatusAndPoisonedAddr(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    uptr &regionPoisonedStatusOrAddr, uint8_t filter = kL1Filter);

#if defined(__cplusplus)
extern "C" {
#endif
/// \retval true only when \p beg is InEnclave & Poisoned
bool RegionIsInEnclaveAndPoisoned(uptr beg, uptr size, uint8_t filter);

int sgx_is_within_enclave(const void *addr, size_t size);
int sgx_is_outside_enclave(const void *addr, size_t size);
#if defined(__cplusplus)
}
#endif
