#pragma once

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"

namespace llvm
{
    class SymbolSaverForLTO
    {
    public:
        SymbolSaverForLTO(Module &M);
        bool runOnModule(Module &M);
        void saveGlobalName2Metadata(Module &M);
        void saveArgName2Metadata(Function &F);
        void saveInstName2Metadata(Function &F);

    private:
        LLVMContext *C;
    };
}