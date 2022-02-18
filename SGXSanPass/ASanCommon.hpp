#pragma once

#include <cstdint>

/// This struct defines the shadow mapping using the rule:
///   shadow = (mem >> Scale) ADD Offset.
struct ShadowMapping
{
    int Scale;
    uint64_t Offset;
};

ShadowMapping getShadowMapping();
uint64_t getRedzoneSizeForScale(int MappingScale);