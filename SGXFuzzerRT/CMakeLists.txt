set(SOURCE
    libFuzzer/FuzzerCrossOver.cpp
    libFuzzer/FuzzerDataFlowTrace.cpp
    libFuzzer/FuzzerDriver.cpp
    libFuzzer/FuzzerExtFunctionsDlsym.cpp
    libFuzzer/FuzzerExtFunctionsWeak.cpp
    libFuzzer/FuzzerExtFunctionsWindows.cpp
    libFuzzer/FuzzerExtraCounters.cpp
    libFuzzer/FuzzerFork.cpp
    libFuzzer/FuzzerInterceptors.cpp
    libFuzzer/FuzzerIO.cpp
    libFuzzer/FuzzerIOPosix.cpp
    libFuzzer/FuzzerIOWindows.cpp
    libFuzzer/FuzzerLoop.cpp
    libFuzzer/FuzzerMain.cpp
    libFuzzer/FuzzerMerge.cpp
    libFuzzer/FuzzerMutate.cpp
    libFuzzer/FuzzerSHA1.cpp
    libFuzzer/FuzzerTracePC.cpp
    libFuzzer/FuzzerUtil.cpp
    libFuzzer/FuzzerUtilDarwin.cpp
    libFuzzer/FuzzerUtilFuchsia.cpp
    libFuzzer/FuzzerUtilLinux.cpp
    libFuzzer/FuzzerUtilPosix.cpp
    libFuzzer/FuzzerUtilWindows.cpp
    libFuzzerCallback.cpp)


include_directories(
    libFuzzer
    ../json/single_include
    ${LINUX_SGX_MINI}/common/inc)

add_library(
    SGXFuzzerRT STATIC 
    ${SOURCE})

set_target_properties(
    SGXFuzzerRT PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-builtin-declaration-mismatch -Wno-unused-result")
