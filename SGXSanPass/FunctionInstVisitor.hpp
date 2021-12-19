#pragma once

#include "llvm/IR/InstVisitor.h"

class FunctionInstVisitor : public llvm::InstVisitor<FunctionInstVisitor>
{
public:
    FunctionInstVisitor(llvm::Function &F) : mFunction(F) {}

    void visitReturnInst(llvm::ReturnInst &RI)
    {
        mReturnInstVec.push_back(&RI);
    }

    void getInstVec(llvm::SmallVector<llvm::Instruction *, 8> &ReturnInstVec)
    {
        for (llvm::BasicBlock *BB : llvm::depth_first(&mFunction.getEntryBlock()))
            visit(*BB);
        ReturnInstVec = mReturnInstVec;
    }

private:
    llvm::Function &mFunction;
    llvm::SmallVector<llvm::Instruction *, 8> mReturnInstVec;
};