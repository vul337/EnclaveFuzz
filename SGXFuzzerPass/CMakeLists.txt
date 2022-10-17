# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    message(FATAL_ERROR "Please specify LLVM Path, e.g. \"export LLVM_DIR=/usr/lib/llvm\"")
endif()

message(STATUS "Find LLVM_DIR: ${LLVM_DIR}")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM_DIR: ${LLVM_INSTALL_PREFIX}")

include_directories(${LLVM_INCLUDE_DIRS} ../json/single_include)
add_library(SGXFuzzerPass MODULE SGXFuzzerPass.cpp DriverGen.cpp)
set_target_properties(SGXFuzzerPass PROPERTIES COMPILE_FLAGS "-Wall -fno-rtti")
