set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

include_directories(../SGXSanRTCommon ../)
add_library(SGXSanRTApp SHARED SGXSanRTApp.cpp)
