#pragma once
#include "SGXSanRT.h"
#include "arch.h"
#include "se_event.h"
#include "thread_data.h"
#include <map>
#include <pthread.h>
#include <stddef.h>

struct TrustThread {
  tcs_t m_tcs;
  int m_event = 0;
  thread_data_t m_td;
};

const int MaxTrustThreadCnt = 8;

class TrustThreadPool {
public:
  TrustThreadPool() {
    for (int i = 0; i < MaxTrustThreadCnt; i++) {
      m_usage_map[&m_threads[i]] = 0;
    }
  }

  TrustThread *alloc(pid_t tid) {
    sgxsan_assert(tid != 0);
    pthread_mutex_lock(&m_mutex);
    TrustThread *thread = nullptr;
    while ((thread = get_free_thread()) == nullptr) {
      pthread_cond_wait(&m_free_cond, &m_mutex);
    }
    sgxsan_assert(thread);
    m_usage_map[thread] = tid;
    pthread_mutex_unlock(&m_mutex);
    return thread;
  }

  void free(TrustThread *thread) {
    pthread_mutex_lock(&m_mutex);
    pid_t &tid = m_usage_map[thread];
    sgxsan_assert(tid != 0);
    tid = 0;
    pthread_cond_signal(&m_free_cond);
    pthread_mutex_unlock(&m_mutex);
  }

  TrustThread *get(pid_t tid) {
    for (auto pair : m_usage_map) {
      if (pair.second == tid) {
        return pair.first;
      }
    }
    return nullptr;
  }

private:
  TrustThread *get_free_thread() {
    for (auto pair : m_usage_map) {
      if (pair.second == 0) {
        return pair.first;
      }
    }
    return nullptr;
  }

  std::map<TrustThread *, pid_t> m_usage_map;
  TrustThread m_threads[MaxTrustThreadCnt];
  pthread_mutex_t m_mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t m_free_cond = PTHREAD_COND_INITIALIZER;
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