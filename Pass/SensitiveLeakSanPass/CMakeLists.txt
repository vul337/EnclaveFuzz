cmake_minimum_required(VERSION 3.16)
project(SensitiveLeakSanPass)

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT DEFINED LLVM_DIR)
    message(FATAL_ERROR "Please specify LLVM Path, e.g. \"export LLVM_DIR=/usr/lib/llvm-12\"")
endif()

# get SVF direcory
set(SVF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../SVF")

if(NOT DEFINED SVF_MODE)
    set(SVF_MODE "Release")
elseif(NOT (SVF_MODE MATCHES "^(Release|Debug)$"))
    message(FATAL_ERROR "SVF_MODE must be \"Debug\" or \"Release\"(Default)")
endif()
message(STATUS "SVF_MODE: ${SVF_MODE}")

# Add the location of LLVMConfig.cmake to CMake search paths (so that find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ${SVF_DIR}/include ../../SGXSanManifest ../PassCommon)

# LLVM is normally built without RTTI. Be consistent with that.
# if(NOT LLVM_ENABLE_RTTI)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti")
# endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../PassCommon PassCommon)

add_library(SensitiveLeakSanPass MODULE SensitiveLeakSanPass.cpp SensitiveLeakSan.cpp)

target_link_libraries(SensitiveLeakSanPass ${SVF_DIR}/${SVF_MODE}-build/lib/libSvf.a ${SVF_DIR}/${SVF_MODE}-build/lib/CUDD/libCudd.a LLVMDemangle PassCommon)
