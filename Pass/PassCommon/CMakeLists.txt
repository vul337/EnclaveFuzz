include_directories(${LLVM_INCLUDE_DIRS} ../../SGXSanManifest)
add_library(PassCommon STATIC PassCommon.cpp SGXSanInstVisitor.cpp)
# this static library will linked with other component and output a DSO, thus make pic on
set_target_properties(PassCommon PROPERTIES POSITION_INDEPENDENT_CODE ON)
