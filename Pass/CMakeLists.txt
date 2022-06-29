cmake_minimum_required(VERSION 3.16)
project(Pass)

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    message(FATAL_ERROR "Please specify LLVM Path, e.g. \"export LLVM_DIR=/usr/lib/llvm-13\"")
endif()
message(STATUS "LLVM_DIR: ${LLVM_DIR}")
# Add the location of LLVMConfig.cmake to CMake search paths (so that find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)

# get SVF direcory
set(SVF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../SVF")
get_filename_component(SVF_DIR ${SVF_DIR} ABSOLUTE)
# get SVF Mode
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(SVF_MODE "Debug")
else()
    set(SVF_MODE "Release")
endif()
set(SVF_BUILD "${SVF_DIR}/${SVF_MODE}-build")
set(SVF_INCLUDE "${SVF_DIR}/include")
message(STATUS "SVF_BUILD: ${SVF_BUILD}")

# LLVM is normally built without RTTI. Be consistent with that.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-unused -Wno-comment -fno-rtti")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/SensitiveLeakSanPass/config.h @ONLY)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/PassCommon PassCommon)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/SGXSanPass SGXSanPass)
# 1. Already merge SensitiveLeakSanPass to SGXSanPass
# 2. Please use ld.lld option "-save-temps" instead of SymbolSaverForLTOPass, to keep symbol value table on LTO

install(TARGETS SGXSanPass
        LIBRARY DESTINATION .)