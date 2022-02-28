cmake_minimum_required(VERSION 3.16)
project(SymbolSaverForLTOPass)

set(LEONE_LLVM_INSTALL_DIR "/opt/llvm")

# Add the location of LLVMConfig.cmake to CMake search paths (so that find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LEONE_LLVM_INSTALL_DIR}/lib/cmake/llvm/")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ../PassCommon ../../SGXSanManifest)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

add_subdirectory(../PassCommon PassCommon)

add_library(SymbolSaverForLTOPass MODULE SymbolSaverForLTOPass.cpp SymbolSaverForLTO.cpp)

target_link_libraries(SymbolSaverForLTOPass PassCommon)