#pragma once

#include "SGXSanInt.h"

// This structure describes an instrumented global variable.
struct __asan_global
{
    uptr beg;                // The address of the global.
    uptr size;               // The original size of the global.
    uptr size_with_redzone;  // The size with the redzone.
    const char *name;        // Name as a C string.
    const char *module_name; // Module name as a C string. This pointer is a
                             // unique identifier of a module.
    uptr odr_indicator;      // The address of the ODR indicator symbol.
};

#if defined(__cplusplus)
extern "C"
{
#endif
    void __asan_register_globals(__asan_global *globals, uptr n);
    void __asan_unregister_globals(__asan_global *globals, uptr n);
#if defined(__cplusplus)
}
#endif
