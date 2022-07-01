# Locate LLVM
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    message(FATAL_ERROR "Please specify LLVM Path, e.g. \"export LLVM_DIR=/usr/lib/llvm\"")
endif()

message(STATUS "LLVM_DIR: ${LLVM_DIR}")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM_DIR: ${LLVM_INSTALL_PREFIX}")

# Locate SVF
set(SVF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../SVF")
get_filename_component(SVF_DIR ${SVF_DIR} ABSOLUTE)
message(STATUS "SVF_DIR: ${SVF_DIR}")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(SVF_MODE "Debug")
else()
    set(SVF_MODE "Release")
endif()

# LLVM is normally built without RTTI. Be consistent with that.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti -std=c++17 -Wno-comment")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/SGXSanPassConfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/SGXSanPassConfig.h @ONLY)

include_directories(${LLVM_INCLUDE_DIRS} ${SVF_DIR}/include .)
add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp PassUtil.cpp SensitiveLeakSanitizer.cpp)
target_link_libraries(SGXSanPass ${SVF_DIR}/${SVF_MODE}-build/lib/libSvf.a ${SVF_DIR}/${SVF_MODE}-build/lib/CUDD/libCudd.a LLVMDemangle)
