#include <string.h>
#include "SGXSanPoison.hpp"

void __asan_set_shadow_00(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0, size);
}

void __asan_set_shadow_f1(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0xf1, size);
}

void __asan_set_shadow_f2(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0xf2, size);
}

void __asan_set_shadow_f3(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0xf3, size);
}

void __asan_set_shadow_f5(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0xf5, size);
}

void __asan_set_shadow_f8(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0xf8, size);
}

void __asan_set_shadow_fe(uptr addr, uptr size)
{
    memset_s((void *)addr, size, 0xfe, size);
}