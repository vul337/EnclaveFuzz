cmake_minimum_required(VERSION 3.16)
project(Pass)

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    message(FATAL_ERROR "Please specify LLVM Path, e.g. \"export LLVM_DIR=/usr/lib/llvm-12\"")
endif()
message(STATUS "LLVM_DIR: ${LLVM_DIR}")
# Add the location of LLVMConfig.cmake to CMake search paths (so that find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)

# get SVF direcory
set(SVF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../SVF")
message(STATUS "SVF_DIR: ${SVF_DIR}")
# get SVF Mode
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(SVF_MODE "Debug")
else()
    set(SVF_MODE "Release")
endif()
message(STATUS "SVF_MODE: ${SVF_MODE}")

# LLVM is normally built without RTTI. Be consistent with that.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-unused -Wno-comment -fno-rtti")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/PassCommon PassCommon)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/SGXSanPass SGXSanPass)
# current merge SensitiveLeakSanPass to SGXSanPass
# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/SensitiveLeakSanPass SensitiveLeakSanPass)
# Please use ld.lld option "-save-temps" instead of SymbolSaverForLTOPass, to keep symbol value table on LTO
# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/SymbolSaverForLTOPass SymbolSaverForLTOPass)

install(TARGETS SGXSanPass
        LIBRARY DESTINATION .)