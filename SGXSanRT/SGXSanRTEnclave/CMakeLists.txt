set(RT_ENCLAVE_SOURCE
    asan_globals.cpp
    CiphertextDetect.cpp
    EncalveTLSLifetime.cpp
    ErrorReport.cpp
    InternalDlmalloc.cpp
    Malloc.cpp
    MemAccessMgr.cpp
    MemIntrinsics.cpp
    MemoryAccessCallback.cpp
    PoisonCheck.cpp
    Poison.cpp
    PoisonSensitiveGlobal.cpp
    Quarantine.cpp
    SGXSanPrintf.cpp
    SGXSanRTEnclave.cpp
    StackTrace.cpp
    ThreadFuncArgShadowStack.cpp
    UntrustSPAdjust.cpp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -Wall -Wextra -Wno-implicit-exception-spec-mismatch -nostdinc -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -Wall -Wextra -Wno-implicit-exception-spec-mismatch -nostdinc -nostdinc++ -fvisibility=hidden -std=c++11")

include_directories(../SGXSanRTCommon ../ ../linux-sgx/common/inc ../linux-sgx/common/inc/internal ../linux-sgx/common/inc/tlibc ../linux-sgx/common/inc/libcxx ../linux-sgx/sdk/cpprt/linux/libunwind/include ../linux-sgx/sdk/cpprt/linux/libunwind/include/tdep-x86_64 ../linux-sgx/sdk/tlibcxx/include ../linux-sgx/sdk/trts .)
add_library(SGXSanRTEnclave STATIC ${RT_ENCLAVE_SOURCE})
set_target_properties(SGXSanRTEnclave PROPERTIES POSITION_INDEPENDENT_CODE True)
