#include "ASanCommon.hpp"
#include "SGXSanManifest.h"
#include <algorithm>

ShadowMapping getShadowMapping()
{
    ShadowMapping Mapping;
    Mapping.Scale = 3;
    Mapping.Offset = SGXSAN_SHADOW_MAP_BASE;
    return Mapping;
}

uint64_t getRedzoneSizeForScale(int MappingScale)
{
    // Redzone used for stack and globals is at least 32 bytes.
    // For scales 6 and 7, the redzone has to be 64 and 128 bytes respectively.
    return std::max(32U, 1U << MappingScale);
}