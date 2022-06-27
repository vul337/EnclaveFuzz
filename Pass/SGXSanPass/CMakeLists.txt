include_directories(${LLVM_INCLUDE_DIRS} ../../SGXSanManifest ../PassCommon ../SensitiveLeakSanPass ${SVF_DIR}/include .)
add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp AdjustUSP.cpp ../SensitiveLeakSanPass/SensitiveLeakSan.cpp)
target_link_libraries(SGXSanPass PassCommon ${SVF_DIR}/${SVF_MODE}-build/lib/libSvf.a ${SVF_DIR}/${SVF_MODE}-build/lib/CUDD/libCudd.a LLVMDemangle)