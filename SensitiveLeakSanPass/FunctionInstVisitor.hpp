#pragma once

#include "llvm/IR/InstVisitor.h"

class FunctionInstVisitor : public llvm::InstVisitor<FunctionInstVisitor>
{
public:
    FunctionInstVisitor(llvm::Function &F)
    {
        for (llvm::BasicBlock *BB : llvm::depth_first(&F.getEntryBlock()))
            visit(*BB);
    }

    void visitReturnInst(llvm::ReturnInst &RI)
    {
        mReturnInstVec.push_back(&RI);
    }

    void getRetInstVec(llvm::SmallVector<llvm::ReturnInst *> &ReturnInstVec)
    {
        ReturnInstVec = mReturnInstVec;
    }

private:
    llvm::SmallVector<llvm::ReturnInst *> mReturnInstVec;
};