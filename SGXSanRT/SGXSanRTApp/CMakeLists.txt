set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

if(HOST_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    message(STATUS "HOST_ASAN Enabled")
endif()

include_directories(../SGXSanRTCommon ../)
add_library(SGXSanRTApp SHARED SGXSanRTApp.cpp)
