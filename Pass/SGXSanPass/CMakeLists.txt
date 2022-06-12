include_directories(${LLVM_INCLUDE_DIRS} ../../SGXSanManifest ../PassCommon)
add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp FunctionStackPoisoner.cpp AdjustUSP.cpp ModuleAddressSanitizer.cpp)
target_link_libraries(SGXSanPass PassCommon)