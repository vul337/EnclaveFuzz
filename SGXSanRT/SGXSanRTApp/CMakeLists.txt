if(NOT ENCLAVE_FILENAME)
    set(ENCLAVE_FILENAME "enclave.signed.so")
endif()
message(STATUS "ENCLAVE_FILENAME: ${ENCLAVE_FILENAME}")

configure_file(config.h.in config.h @ONLY)

add_definitions(-DOUT_ENCLAVE)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

include_directories(../SGXSanRTCommon ../ ${SGX_SDK}/include ${CMAKE_CURRENT_BINARY_DIR})
add_library(SGXSanRTApp SHARED SGXSanRTApp.cpp)
