cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(LINUX_SGX_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/linux-sgx")
set(LINUX_SGX_MINI "${CMAKE_CURRENT_SOURCE_DIR}/SGXSanRT/linux-sgx-mini/")
set(SGXSAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KAFL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/kAFL)
set(KAFL_EXAMPLES_DIR ${KAFL_DIR}/kafl/examples)
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
        ARCHIVE DESTINATION lib64
)

install(DIRECTORY kAFLUSpaceUtil/initrd/
        USE_SOURCE_PERMISSIONS
        DESTINATION initrd)

install(FILES Tool/rand_file
        DESTINATION .)
endif()

install(DIRECTORY
        ${LINUX_SGX_MINI}/common/inc/ DESTINATION include
        PATTERN common/inc/internal EXCLUDE)

install(DIRECTORY
        ${LINUX_SGX_SRC_DIR}/common/inc/ DESTINATION include
        PATTERN common/inc/internal EXCLUDE
        PATTERN common/inc/stdc++ EXCLUDE
        PATTERN common/inc/tlibc EXCLUDE
        PATTERN common/inc/sgx_mm* EXCLUDE
)

install(FILES
        ${LINUX_SGX_SRC_DIR}/external/sgx-emm/emm_src/include/sgx_mm.h
        ${LINUX_SGX_SRC_DIR}/external/sgx-emm/emm_src/include/sgx_mm_primitives.h
        ${LINUX_SGX_SRC_DIR}/external/sgx-emm/emm_src/include/sgx_mm_rt_abstraction.h
        DESTINATION include)

install(FILES Tool/sgx_edger8r
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        DESTINATION bin/x64)

install(FILES ${LINUX_SGX_SRC_DIR}/common/buildenv.mk
        DESTINATION .)
