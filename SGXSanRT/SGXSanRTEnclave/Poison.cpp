#include <string.h>
#include "Poison.hpp"

void __asan_set_shadow_00(uptr addr, uptr size)
{
    memset((void *)addr, 0, size);
}

void __asan_set_shadow_f1(uptr addr, uptr size)
{
    memset((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(uptr addr, uptr size)
{
    memset((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(uptr addr, uptr size)
{
    memset((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(uptr addr, uptr size)
{
    memset((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(uptr addr, uptr size)
{
    memset((void *)addr, 0xf8, size);
}

void __asan_set_shadow_fe(uptr addr, uptr size)
{
    memset((void *)addr, 0xfe, size);
}