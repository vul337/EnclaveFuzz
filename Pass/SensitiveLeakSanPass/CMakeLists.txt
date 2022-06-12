include_directories(${LLVM_INCLUDE_DIRS} ${SVF_DIR}/include ../../SGXSanManifest ../PassCommon)
add_library(SensitiveLeakSanPass MODULE SensitiveLeakSanPass.cpp SensitiveLeakSan.cpp)
target_link_libraries(SensitiveLeakSanPass ${SVF_DIR}/${SVF_MODE}-build/lib/libSvf.a ${SVF_DIR}/${SVF_MODE}-build/lib/CUDD/libCudd.a LLVMDemangle PassCommon)
