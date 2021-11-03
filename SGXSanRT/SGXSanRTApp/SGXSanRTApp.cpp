#include <assert.h>
#include <stdio.h>
#include "SGXSanManifest.h"
#include "SGXSanRTApp.hpp"

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

#define kShadowBeg SGXSAN_SHADOW_MAP_BASE
uptr kShadowEnd = 0, kEnclaveBase = 0, kEnclaveSize = 0;

void PrintAddressSpaceLayout()
{
       printf("|| `[%p, %p]` || Shadow  ||\n",
              (void *)kShadowBeg, (void *)kShadowEnd);
       printf("|| `[%p, %p]` || Elrange ||\n",
              (void *)kEnclaveBase, (void *)(kEnclaveBase + kEnclaveSize - 1));

       printf("SHADOW_SCALE: %d\n", (int)3);
       printf("SHADOW_GRANULARITY: %d\n", (int)8);
}

// create shadow memory outside enclave for elrange
// because shadow is independent of elrange, we just need one block of memory for shadow, and don't need consider shadow gap.
void ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr, uptr *shadow_end_ptr)
{
       kEnclaveBase = enclave_base;
       kEnclaveSize = enclave_size;

       uptr shadow_start = kShadowBeg;
       kShadowEnd = (enclave_size >> 3) + kShadowBeg - 1;

       bool full_shadow_is_available = false;

       shadow_start -= __sanitizer::GetMmapGranularity();

       if (!full_shadow_is_available)
              full_shadow_is_available =
                  __sanitizer::MemoryRangeIsAvailable(shadow_start, kShadowEnd);

       PrintAddressSpaceLayout();

       assert(full_shadow_is_available);

       // mmap the shadow plus at least one page at the left.
       __sanitizer::ReserveShadowMemoryRange(shadow_start, kShadowEnd, "shadow");

       *shadow_beg_ptr = kShadowBeg;
       *shadow_end_ptr = kShadowEnd;
}