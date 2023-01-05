include_directories(${LLVM_INCLUDE_DIRS} ../json/single_include ../SGXSanPass/)
add_library(SGXFuzzerPass MODULE SGXFuzzerPass.cpp DriverGen.cpp ../SGXSanPass/PassUtil.cpp)
set_target_properties(SGXFuzzerPass PROPERTIES COMPILE_FLAGS "-Wall -fno-rtti")
