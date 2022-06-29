
include_directories(${LLVM_INCLUDE_DIRS} ${SVF_INCLUDE} ../../SGXSanManifest ../PassCommon .)
add_library(SensitiveLeakSanPass MODULE SensitiveLeakSanPass.cpp SensitiveLeakSan.cpp)
target_link_libraries(SensitiveLeakSanPass ${SVF_BUILD}/lib/libSvf.a ${SVF_BUILD}/lib/CUDD/libCudd.a LLVMDemangle PassCommon)
