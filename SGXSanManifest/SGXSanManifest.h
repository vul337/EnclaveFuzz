#ifndef SGXSAN_MANIFEST_H
#define SGXSAN_MANIFEST_H

#ifndef SGXSAN_DEBUG
#define SGXSAN_DEBUG 1
#endif

// after modification, need rebuild both rt and pass
#define SGXSAN_SHADOW_MAP_BASE 0x7fff8000

// current may only support granularity 8
#define SHADOW_GRANULARITY 8

#endif
