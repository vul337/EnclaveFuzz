include_directories(${LLVM_INCLUDE_DIRS} ../json/single_include ../SGXSanPass/ ../SGXFuzzerRT)
add_library(SGXFuzzerPass MODULE SGXFuzzerPass.cpp DriverGen.cpp ../SGXSanPass/PassUtil.cpp ../SGXSanPass/LLVMStructTypeSerialize.cpp)
set_target_properties(SGXFuzzerPass PROPERTIES COMPILE_FLAGS "-Wall -fno-rtti -std=c++17")
