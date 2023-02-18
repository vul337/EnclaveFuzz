cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(CMAKE_C_COMPILER "clang-13")
set(CMAKE_CXX_COMPILER "clang++-13")

set(SGXSAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
configure_file(SGXSanConfig.h.in SGXSanConfig.h @ONLY)

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

install(TARGETS
        SGXSanPass
        SGXSanRTApp
        SGXSanRTEnclave
        SGXFuzzerPass
        SGXFuzzerRT
        FuncRenamePass
        GetOCallTable
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(FILES SGXSanRT/SGXSanRTEnclave/SGXSanRTEnclave.edl
        DESTINATION include)

install(FILES Tool/sgx_edger8r
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION bin/x64)
