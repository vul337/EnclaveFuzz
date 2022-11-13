#pragma once

#define DUMP_STACK_TRACE 1
// 0 -> LOG_LEVEL_NONE,
// 1 -> LOG_LEVEL_ERROR,
// 2 -> LOG_LEVEL_WARNING, (Default)
// 3 -> LOG_LEVEL_DEBUG,
// 4 -> LOG_LEVEL_TRACE,
#define USED_LOG_LEVEL 2

#define SHADOW_OFFSET 0x18000000000ULL /* 1.5 TB */
#define ENCLAVE_FILENAME "enclave.signed.so"
