cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(CMAKE_C_COMPILER "clang-13")
set(CMAKE_CXX_COMPILER "clang++-13")

set(LINUX_SGX_MINI "${CMAKE_CURRENT_SOURCE_DIR}/SGXSanRT/linux-sgx-mini/")
set(SGXSAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    set(LLVM_DIR "/usr/lib/llvm-13")
endif()

message(STATUS "LLVM_DIR: ${LLVM_DIR}")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM_DIR: ${LLVM_INSTALL_PREFIX}")

add_subdirectory(SGXSanPass)
add_subdirectory(SGXSanRT)
add_subdirectory(SGXFuzzerPass)
add_subdirectory(SGXFuzzerRT)

if(LIBFUZZER_CB_ASAN)
    message(STATUS "LIBFUZZER_CB_ASAN: Enable")
    add_dependencies(SGXFuzzerRT SGXSanPass)
else()
    message(STATUS "LIBFUZZER_CB_ASAN: Disable")
endif()

install(TARGETS
        SGXSanPass
        SGXSanRTApp
        SGXSanRTEnclave
        SGXFuzzerPass
        SGXFuzzerRTHost
        SGXFuzzerRT
        FuncRenamePass
        GetOCallTable
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(DIRECTORY
        ${LINUX_SGX_MINI}/common/inc/ DESTINATION include
        PATTERN common/inc/internal EXCLUDE)

install(FILES Tool/sgx_edger8r
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION bin/x64)

install(FILES ${LINUX_SGX_MINI}/common/buildenv.mk
        DESTINATION .)

install(FILES kAFLUSpaceUtil/libnyx_agent.a
        kAFLUSpaceUtil/libnyx_agent.so
        DESTINATION lib64)

install(FILES kAFLUSpaceUtil/vmcall
        DESTINATION bin)

install(FILES Tool/rand_file
        DESTINATION .)