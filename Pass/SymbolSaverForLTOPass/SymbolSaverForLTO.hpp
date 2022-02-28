#pragma once

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"

class SymbolSaverForLTO
{
public:
    SymbolSaverForLTO(llvm::Module &M);
    bool runOnModule(llvm::Module &M);
    void saveGlobalName2Metadata(llvm::Module &M);
    void saveArgName2Metadata(llvm::Function &F);
    void saveInstName2Metadata(llvm::Function &F);

private:
    llvm::LLVMContext *C;
};