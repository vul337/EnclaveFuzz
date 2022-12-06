#pragma once
#include "SGXSanRTApp.h"

enum ECallCheckType { CHECK_ECALL_PRIVATE, CHECK_ECALL_ALLOWED };

#if defined(__cplusplus)
extern "C" {
#endif
void PoisonEnclaveDSOCodeSegment();

void SGXSAN(__sanitizer_cov_8bit_counters_init)(uint8_t *Start, uint8_t *Stop);
void SGXSAN(__sanitizer_cov_pcs_init)(const uintptr_t *pcs_beg,
                                      const uintptr_t *pcs_end);
#if defined(__cplusplus)
}
#endif