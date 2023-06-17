cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(SGXSAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KAFL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/kAFL")
set(KAFL_EXAMPLES_DIR "${KAFL_DIR}/kafl/examples")
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
if(KAFL_FUZZER)
message(STATUS "Fuzzer: kAFL")
add_subdirectory(kAFLUSpaceUtil)
else()
message(STATUS "Fuzzer: libFuzzer")
endif()

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
if(KAFL_FUZZER)
install(TARGETS
        nyx_agent
        nyx_agent_static
        vmcall
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(DIRECTORY kAFLUSpaceUtil/initrd/
USE_SOURCE_PERMISSIONS
DESTINATION initrd)

install(FILES Tool/rand_file
DESTINATION .)

endif()

install(FILES SGXSanRT/SGXSanRTEnclave/SGXSanRTEnclave.edl
        DESTINATION include)

install(FILES Tool/sgx_edger8r
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION bin/x64)

install(DIRECTORY linux-sgx/common/inc/
        DESTINATION include
        PATTERN "linux-sgx/common/inc/internal" EXCLUDE)

install(DIRECTORY linux-sgx/sdk/tlibcxx/include/
        DESTINATION include/libcxx)

install(DIRECTORY linux-sgx/external/ippcp_internal/inc/
        DESTINATION include/ipp
        PATTERN "ippcp20u3.patch" EXCLUDE)

install(DIRECTORY linux-sgx/external/dcap_source/QuoteGeneration/pce_wrapper/inc/
        DESTINATION include)

install(FILES linux-sgx/common/buildenv.mk
        DESTINATION .)
