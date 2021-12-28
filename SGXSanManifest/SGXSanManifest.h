#ifndef SGXSAN_MANIFEST_H
#define SGXSAN_MANIFEST_H

#ifndef SGXSAN_DEBUG
#define SGXSAN_DEBUG 1
#endif

// after modification, need rebuild both rt and pass
#define SGXSAN_SHADOW_MAP_BASE 0x7fff8000

// current may only support granularity 8
#define SHADOW_GRANULARITY 8

#define CHECK_MALLOC_FREE_MATCH 1

// USE_SGXSAN_MALLOC set 1 means we wrap malloc directly and some malloc replaced to sgxsan_malloc by pass will be hooked,
// other mallocs which are not influenced by pass will not be hooked.
// USE_SGXSAN_MALLOC==1 will miss some malloc-serial operation in third-party library
#define USE_SGXSAN_MALLOC 0

#endif
