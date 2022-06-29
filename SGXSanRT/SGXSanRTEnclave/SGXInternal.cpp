#include "SGXInternal.hpp"

const char *layout_id_str[] = {"Undefined",     "HEAP_MIN",
                               "HEAP_INIT",     "HEAP_MAX",
                               "TCS",           "TD",
                               "SSA",           "STACK_MAX",
                               "STACK_MIN",     "THREAD_GROUP",
                               "GUARD",         "HEAP_DYN_MIN",
                               "HEAP_DYN_INIT", "HEAP_DYN_MAX",
                               "TCS_DYN",       "TD_DYN",
                               "SSA_DYN",       "STACK_DYN_MAX",
                               "STACK_DYN_MIN", "THREAD_GROUP_DYN",
                               "RSRV_MIN",      "RSRV_INIT",
                               "RSRV_MAX"};

const void *get_tcs(void) {
  thread_data_t *td = get_thread_data();
  return TD2TCS(td);
}
