#include <assert.h>
#include <stdio.h>
#include "SGXSanManifest.h"
#include "SGXSanRTApp.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanEnclaveConfigReader.hpp"

// read ENCLAVE_FILENAME from -DENCLAVE_FILENAME in makefile
#ifndef ENCLAVE_FILENAME
#define ENCLAVE_FILENAME "enclave.signed.so"
#endif
// pass string to ENCLAVE_FILENAME (https://stackoverflow.com/questions/54602025/how-to-pass-a-string-from-a-make-file-into-a-c-program)
#define xstr(s) str(s)
#define str(s) #s

namespace __sanitizer
{
       uptr GetMmapGranularity();

       // Used to check if we can map shadow memory to a fixed location.
       bool MemoryRangeIsAvailable(uptr range_start, uptr range_end);

       // Reserve memory range [beg, end]. If madvise_shadow is true then apply
       // madvise (e.g. hugepages, core dumping) requested by options.
       void ReserveShadowMemoryRange(uptr beg, uptr end, const char *name,
                                     bool madvise_shadow = true);
}

uptr g_enclave_base = 0, g_enclave_size = 0;
uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
         kLowShadowBeg = 0, kLowShadowEnd = 0,
         kShadowGapBeg = 0, kShadowGapEnd = 0,
         kHighShadowBeg = 0, kHighShadowEnd = 0,
         kHighMemBeg = 0, kHighMemEnd = 0;

void PrintAddressSpaceLayout()
{
       printf("|| `[%p, %p]` || Shadow  ||\n",
              (void *)kLowShadowBeg, (void *)kLowShadowEnd);
       printf("|| `[%p, %p]` || Elrange ||\n",
              (void *)g_enclave_base, (void *)(g_enclave_base + g_enclave_size - 1));
}

// create shadow memory outside enclave for elrange
// because shadow is independent of elrange, we just need one block of memory for shadow, and don't need consider shadow gap.
void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr)
{
       g_enclave_base = enclave_base;
       g_enclave_size = enclave_size;

       // only use LowMem and LowShadow as ELRANGE and EnclaveShadow
       kLowShadowBeg = SGXSAN_SHADOW_MAP_BASE;
       kLowShadowEnd = (enclave_size >> 3) + kLowShadowBeg - 1;
       kLowMemBeg = g_enclave_base;
       kLowMemEnd = g_enclave_base + enclave_size - 1;

       uptr shadow_start = kLowShadowBeg;

       bool full_shadow_is_available = false;

       shadow_start -= __sanitizer::GetMmapGranularity();

       if (!full_shadow_is_available)
              full_shadow_is_available =
                  __sanitizer::MemoryRangeIsAvailable(shadow_start, kLowShadowEnd);

       PrintAddressSpaceLayout();

       assert(full_shadow_is_available);

       // fix-me: may need unmap at destructor
       // mmap the shadow plus at least one page at the left.
       __sanitizer::ReserveShadowMemoryRange(shadow_start, kLowShadowEnd, "shadow");

       *shadow_beg_ptr = kLowShadowBeg;
       *shadow_end_ptr = kLowShadowEnd;

       // start shallow poison on sensitive layout
       SGXSanEnclaveConfigReader reader{g_enclave_base};
       // printf("ENCLAVE_FILENAME=%s\n", xstr(ENCLAVE_FILENAME));
       reader.collect_layout_infos(xstr(ENCLAVE_FILENAME));
       reader.shallow_poison_senitive();
}