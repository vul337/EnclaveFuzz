set(SOURCE
    libFuzzerCallback.cpp)

if(HOST_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    message(STATUS "HOST_ASAN Enabled")
endif()

include_directories(
    ../json/single_include)

add_library(
    SGXFuzzerRT STATIC 
    ${SOURCE})

set_target_properties(
    SGXFuzzerRT PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall")
