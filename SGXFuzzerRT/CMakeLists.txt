set(SOURCE
    libFuzzerCallback.cpp)


include_directories(
    ../json/single_include)

add_library(
    SGXFuzzerRT STATIC 
    ${SOURCE})

set_target_properties(
    SGXFuzzerRT PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall")
