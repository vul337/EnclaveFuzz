set(SOURCE
    libFuzzerCallback.cpp)


include_directories(
    ../../json/single_include)

add_library(
    SGXFuzzerRTApp STATIC 
    ${SOURCE})

set_target_properties(
    SGXFuzzerRTApp PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall")
