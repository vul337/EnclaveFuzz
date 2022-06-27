#pragma once

#include "SGXSanInt.h"

// This structure is used to describe the source location of a place where
// global was defined.
struct __asan_global_source_location
{
    const char *filename;
    int line_no;
    int column_no;
};

// This structure describes an instrumented global variable.
struct __asan_global
{
    uptr beg;                                // The address of the global.
    uptr size;                               // The original size of the global.
    uptr size_with_redzone;                  // The size with the redzone.
    const char *name;                        // Name as a C string.
    const char *module_name;                 // Module name as a C string. This pointer is a
                                             // unique identifier of a module.
    uptr has_dynamic_init;                   // Non-zero if the global has dynamic initializer.
    __asan_global_source_location *location; // Source location of a global,
                                             // or NULL if it is unknown.
    uptr odr_indicator;                      // The address of the ODR indicator symbol.
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
