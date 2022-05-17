cmake_minimum_required(VERSION 3.16)
project(SGXSanPass)

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    message(FATAL_ERROR "Please specify LLVM Path, e.g. \"export LLVM_DIR=/usr/lib/llvm-12\"")
endif()

# Add the location of LLVMConfig.cmake to CMake search paths (so that find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ../../SGXSanManifest ../PassCommon)

# LLVM is normally built without RTTI. Be consistent with that.
# if(NOT LLVM_ENABLE_RTTI)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti")
# endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../PassCommon PassCommon)

add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp FunctionStackPoisoner.cpp AdjustUSP.cpp ModuleAddressSanitizer.cpp)

target_link_libraries(SGXSanPass PassCommon)