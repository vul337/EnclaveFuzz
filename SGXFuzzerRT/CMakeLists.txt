include_directories(
    libFuzzer
    ../json/single_include
    ../magic_enum/include
    ../kAFLUSpaceUtil/include
    ${CMAKE_CURRENT_BINARY_DIR}/..
    ${LINUX_SGX_MINI}/common/inc
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer)

add_library(
    SGXFuzzerRTHost STATIC 
    Harness.cpp)

set_target_properties(
    SGXFuzzerRTHost PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-unused-result -std=c++17")

get_filename_component(SGXSanPassPath ${CMAKE_BINARY_DIR}/SGXSanPass/libSGXSanPass.so ABSOLUTE)
if(LIBFUZZER_CB_ASAN)
    set_source_files_properties(${FUZZER_RT_SRC} PROPERTIES
        COMPILE_FLAGS "-flegacy-pass-manager -Xclang -load -Xclang ${SGXSanPassPath} -mllvm -in-enclave=false")
endif()

add_library(
    SGXFuzzerRT STATIC 
    Harness.cpp)

set_target_properties(
    SGXFuzzerRT PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-unused-result -std=c++17")

target_compile_definitions(SGXFuzzerRT PUBLIC IN_KAFL_QEMU)
