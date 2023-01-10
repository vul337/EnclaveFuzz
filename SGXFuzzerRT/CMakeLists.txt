set(LIBFUZZER_SRC
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
    libFuzzer/FuzzerUtilWindows.cpp)

set(FUZZER_RT_SRC
    libFuzzerCallback.cpp)


include_directories(
    libFuzzer
    ../json/single_include
    ../magic_enum/include
    ${CMAKE_CURRENT_BINARY_DIR}/..
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer)

if(KAFL_FUZZER)
include_directories(
    ${KAFL_EXAMPLES_DIR}/linux-user/libnyx_agent/src/
    ${KAFL_EXAMPLES_DIR}
)
add_library(
    SGXFuzzerRT STATIC 
    ${FUZZER_RT_SRC})
target_compile_definitions(SGXFuzzerRT PUBLIC KAFL_FUZZER)
else()
add_library(
    SGXFuzzerRT STATIC 
    ${LIBFUZZER_SRC}
    ${FUZZER_RT_SRC})
endif()

set_target_properties(
    SGXFuzzerRT PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-unused-result -std=c++17")

get_filename_component(SGXSanPassPath ${CMAKE_BINARY_DIR}/SGXSanPass/libSGXSanPass.so ABSOLUTE)
if(LIBFUZZER_CB_ASAN)
    set_source_files_properties(${FUZZER_RT_SRC} PROPERTIES
        COMPILE_FLAGS "-flegacy-pass-manager -Xclang -load -Xclang ${SGXSanPassPath} -mllvm -in-enclave=false")
endif()
