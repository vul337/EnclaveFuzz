set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

if(HOST_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    message(STATUS "HOST_ASAN Enabled")
endif()

include_directories(../SGXSanRTCommon ../ ../../linux-sgx/common/inc)
add_library(SGXSanRTApp SHARED SGXSanRTApp.cpp)
if(KAFL_FUZZER)
target_compile_definitions(SGXSanRTApp PUBLIC KAFL_FUZZER)
endif()
