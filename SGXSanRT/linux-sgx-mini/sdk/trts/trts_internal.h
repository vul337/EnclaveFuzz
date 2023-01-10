#pragma once
#include "SGXSanRTApp.h"
#include "arch.h"
#include "se_event.h"
#include "thread_data.h"
#include <map>
#include <pthread.h>
#include <stddef.h>

struct TrustThread {
  tcs_t m_tcs;
  int m_event;
  thread_data_t m_td;
};

static inline tcs_t *td2tcs(thread_data_t *td) {
  TrustThread *thread =
      (TrustThread *)((uintptr_t)td - offsetof(TrustThread, m_td));
  return &thread->m_tcs;
}

static inline se_handle_t tcs2event(tcs_t *tcs) {
  TrustThread *thread =
      (TrustThread *)((uintptr_t)tcs - offsetof(TrustThread, m_tcs));
  return &thread->m_event;
}
#define TD2TCS(td) ((const void *)td2tcs((thread_data_t *)td))