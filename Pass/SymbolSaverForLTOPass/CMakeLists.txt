include_directories(${LLVM_INCLUDE_DIRS} ../PassCommon ../../SGXSanManifest)
add_library(SymbolSaverForLTOPass MODULE SymbolSaverForLTOPass.cpp SymbolSaverForLTO.cpp)
target_link_libraries(SymbolSaverForLTOPass PassCommon)