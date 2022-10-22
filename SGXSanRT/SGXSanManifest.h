#pragma once

#define DUMP_STACK_TRACE 1
// 0 -> LOG_LEVEL_NONE,
// 1 -> LOG_LEVEL_ERROR,
// 2 -> LOG_LEVEL_WARNING, (Default)
// 3 -> LOG_LEVEL_DEBUG,
// 4 -> LOG_LEVEL_TRACE,
#define USED_LOG_LEVEL 2

#define SHOW_TID 0

// after modification, need rebuild both rt and pass
#define SGXSAN_SHADOW_MAP_BASE 0x18000000000ULL
#define SHADOW_SCALE 3

// current may only support granularity 8
#define SHADOW_GRANULARITY (1UL << SHADOW_SCALE)
