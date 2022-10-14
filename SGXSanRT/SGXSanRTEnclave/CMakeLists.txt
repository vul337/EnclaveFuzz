set(RT_ENCLAVE_SOURCE
    asan_globals.cpp
    CiphertextDetect.cpp
    EdgeCheck.cpp
    EncalveTLSLifetime.cpp
    ErrorReport.cpp
    InternalDlmalloc.cpp
    Malloc.cpp
    MemIntrinsics.cpp
    MemoryAccessCallback.cpp
    PoisonCheck.cpp
    Poison.cpp
    PoisonSensitiveGlobal.cpp
    Quarantine.cpp
    SensitivePoisoner.cpp
    SGXInternal.cpp
    SGXSanPrintf.cpp
    SGXSanRTEnclave.cpp
    StackTrace.cpp
    ThreadFuncArgShadowStack.cpp
    UntrustSPAdjust.cpp
    WhitelistCheck.cpp)

add_definitions(-DIN_ENCLAVE)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -Wall -Wextra -nostdinc -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -Wall -Wextra -nostdinc -nostdinc++ -fvisibility=hidden -std=c++11")

include_directories(../SGXSanRTCommon ../ ${SGX_SDK}/include ${SGX_SDK}/include/tlibc ${SGX_SDK}/include/libcxx libunwind/include libunwind/include/tdep-x86_64 .)
add_library(SGXSanRTEnclave STATIC ${RT_ENCLAVE_SOURCE})
set_target_properties(SGXSanRTEnclave PROPERTIES POSITION_INDEPENDENT_CODE True)
