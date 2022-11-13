set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_MINI}/common/inc
    ${LINUX_SGX_MINI}/common/inc/internal
    ../)

add_library(
    SGXSanRTEnclave STATIC 
    TSticker.cpp)

set_target_properties(SGXSanRTEnclave PROPERTIES POSITION_INDEPENDENT_CODE True)