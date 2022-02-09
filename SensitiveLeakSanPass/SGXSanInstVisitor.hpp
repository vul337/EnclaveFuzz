#pragma once

#include "llvm/IR/InstVisitor.h"

class SGXSanInstVisitor : public llvm::InstVisitor<SGXSanInstVisitor>
{
public:
    SGXSanInstVisitor(llvm::Function &F)
    {
        visit(F);
    }

    SGXSanInstVisitor(llvm::Module &M)
    {
        visit(M);
    }

    void visitReturnInst(llvm::ReturnInst &RI)
    {
        mReturnInstVec.push_back(&RI);
    }

    void visitCallInst(llvm::CallInst &CI)
    {
        mCallInstVec.push_back(&CI);
    }

    void getRetInstVec(llvm::SmallVector<llvm::ReturnInst *> &ReturnInstVec)
    {
        ReturnInstVec = mReturnInstVec;
    }

    void getCallInstVec(llvm::SmallVector<llvm::CallInst *> &CallInstVec)
    {
        CallInstVec = mCallInstVec;
    }

private:
    llvm::SmallVector<llvm::ReturnInst *> mReturnInstVec;
    llvm::SmallVector<llvm::CallInst *> mCallInstVec;
};