# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    set(LLVM_DIR "/usr/lib/llvm-13")
endif()
message(STATUS "LLVM_DIR: ${LLVM_DIR}")

# Add the location of LLVMConfig.cmake to CMake search paths (so that find_package can locate it)
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)

# get SVF direcory
set(SVF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../SVF")
get_filename_component(SVF_DIR ${SVF_DIR} ABSOLUTE)
message(STATUS "SVF_DIR: ${SVF_DIR}")

# get SVF Mode
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set(SVF_MODE "Debug")
else()
    set(SVF_MODE "Release")
endif()
message(STATUS "SVF_MODE: ${SVF_MODE}")

# LLVM is normally built without RTTI. Be consistent with that.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-unused-variable -Wno-return-type -fno-rtti -std=c++17")

configure_file(config.h.in config.h @ONLY)

include_directories(${LLVM_INCLUDE_DIRS} ${SVF_DIR}/include ../json/single_include ${CMAKE_CURRENT_BINARY_DIR})
add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp AdjustUSP.cpp SensitiveLeakSan.cpp PassCommon.cpp SGXSanInstVisitor.cpp)
target_link_libraries(SGXSanPass ${SVF_DIR}/${SVF_MODE}-build/lib/libSvf.a)
