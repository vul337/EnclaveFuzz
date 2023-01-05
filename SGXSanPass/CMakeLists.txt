# Locate SVF
set(SVF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../SVF")
get_filename_component(SVF_DIR ${SVF_DIR} ABSOLUTE)
message(STATUS "SVF_DIR: ${SVF_DIR}")

if(NOT SVF_MODE)
    set(SVF_MODE "Release")
endif()
message(STATUS "SVF_MODE: ${SVF_MODE}")

# LLVM is normally built without RTTI. Be consistent with that.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti -std=c++17 -Wno-comment -Wno-unused-but-set-variable -Wno-unused-variable -Wno-maybe-uninitialized")

configure_file(SGXSanPassConfig.h.in SGXSanPassConfig.h @ONLY)

include_directories(${LLVM_INCLUDE_DIRS} ${SVF_DIR}/include ../json/single_include ${SVF_DIR}/z3.obj/include/ ${CMAKE_CURRENT_BINARY_DIR})
add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp PassUtil.cpp SensitiveLeakSanitizer.cpp)
target_link_libraries(SGXSanPass ${SVF_DIR}/${SVF_MODE}-build/lib/libSvf.a)

add_library(FuncRenamePass MODULE FuncRenamePass.cpp)
