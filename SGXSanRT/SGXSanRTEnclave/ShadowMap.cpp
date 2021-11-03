#include "ShadowMap.hpp"

uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
         kLowShadowBeg = 0, kLowShadowEnd = 0,
         kShadowGapBeg = 0, kShadowGapEnd = 0,
         kHighShadowBeg = 0, kHighShadowEnd = 0,
         kHighMemBeg = 0, kHighMemEnd = 0;