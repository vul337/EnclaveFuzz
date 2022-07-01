#pragma once

#include "SGXSanRT.h"
#include <stdint.h>
#include <utility>

enum InOutEnclaveStatus {
  UnknownInOutEnclaveStatus = -1,
  OutEnclave = 0,
  InEnclave = 1
};
enum PoisonStatus { UnknownPoisonStatus = -1, NotPoisoned = 0, IsPoisoned = 1 };

#if defined(__cplusplus)
extern "C" {
#endif

/// \retval 1) \c InOutEnclaveStatus will never be \c Unknown
/// \retval 2) If \c InOutEnclaveStatus == \c InEnclave,
/// \c PoisonStatus will never be \c Unknown.
/// \retval 3) If \c InOutEnclaveStatus == \c OutEnclave,
/// \c PoisonStatus is \c Unknown and has no meaning.
std::pair<InOutEnclaveStatus, PoisonStatus>
AddressInOutEnclaveStatusAndPoisonStatus(uptr addr, uint8_t filter = 0x8F);

/// \retval 1) \c InOutEnclaveStatus: If \p size is too large, we may return \c
/// UnknownInOutEnclaveStatus
/// \retval 2) \c PoisonStatus: Return \c IsPoisoned
/// if we can quickly decide that the region is unpoisoned. We assume that a
/// redzone is at least 16 bytes.
std::pair<InOutEnclaveStatus, PoisonStatus>
FastRegionInOutEnclaveStatusAndPoisonStatus(uptr beg, uptr size);

/// Tell us whether region is poisoned, even if it's partial poisoned (what
/// 'Strct' means)
/// \retval 1) \c InOutEnclaveStatus will never be \c Unknown
/// \retval 2) If \c InOutEnclaveStatus == \c InEnclave,
/// \c PoisonStatus will never be \c Unknown.
/// \retval 3) If \c InOutEnclaveStatus == \c OutEnclave,
/// \c PoisonStatus is \c Unknown and has no meaning.
std::pair<InOutEnclaveStatus, PoisonStatus>
RegionInOutEnclaveStatusAndStrictPoisonStatus(uint8_t *beg, uptr size,
                                               uint8_t filter = 0x8F);

/// Tell us whether region is poisoned, partial poisoned will be checked
/// \param need_poisoned_addr if we needn't get poisoned address, it run faster
/// \retval 1) \c InOutEnclaveStatus : Will never be \c Unknown
/// \retval 2) If \c InOutEnclaveStatus == \c InEnclave, \c uptr == 0 means
/// unpoisoned
/// \retval 3) If \c InOutEnclaveStatus == \c OutEnclave, \c uptr has no
/// meaning
std::pair<InOutEnclaveStatus, uptr>
RegionInOutEnclaveStatusAndPoisonStatus(uptr beg, uptr size,
                                        uint8_t filter = 0x8F,
                                        bool need_poisoned_addr = false);

/// \retval true only when \p beg is InEnclave & Poisoned
bool RegionIsInEnclaveAndPoisoned(uptr beg, uptr size, uint8_t filter);

int sgx_is_within_enclave(const void *addr, size_t size);
int sgx_is_outside_enclave(const void *addr, size_t size);
#if defined(__cplusplus)
}
#endif
