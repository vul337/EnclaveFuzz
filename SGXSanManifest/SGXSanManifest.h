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
#define SGXSAN_SHADOW_MAP_BASE 0x7fff8000

// current may only support granularity 8
#define SHADOW_GRANULARITY 8

// USE_SGXSAN_MALLOC set 1 means we wrap malloc directly and some malloc replaced to sgxsan_malloc by pass will be hooked,
// other mallocs which are not influenced by pass will not be hooked. Thus, USE_SGXSAN_MALLOC==1 will miss some malloc-serial operation in third-party library
#define USE_SGXSAN_MALLOC 0
