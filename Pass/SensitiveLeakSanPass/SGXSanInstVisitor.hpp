#pragma once

#include "llvm/IR/InstVisitor.h"
#include "llvm/Analysis/ValueTracking.h"

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

    void visitIntrinsicInst(llvm::IntrinsicInst &II)
    {
        for (auto CI : mCallInstVec)
        {
            if (CI == &II)
                abort();
        }
        mCallInstVec.push_back(llvm::cast<llvm::CallInst>(&II));

        auto ID = II.getIntrinsicID();
        if (ID == llvm::Intrinsic::lifetime_start)
        {
            llvm::AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
            mAILifeTimeStart[AI].push_back(&II);
        }
    }

    void getRetInstVec(llvm::SmallVector<llvm::ReturnInst *> &ReturnInstVec)
    {
        ReturnInstVec = mReturnInstVec;
    }

    void getCallInstVec(llvm::SmallVector<llvm::CallInst *> &CallInstVec)
    {
        CallInstVec = mCallInstVec;
    }

    void getAILifeTimeStart(llvm::SmallDenseMap<llvm::AllocaInst *, llvm::SmallVector<llvm::IntrinsicInst *>> &AILifeTimeStart)
    {
        AILifeTimeStart = mAILifeTimeStart;
    }

private:
    llvm::SmallVector<llvm::ReturnInst *> mReturnInstVec;
    llvm::SmallVector<llvm::CallInst *> mCallInstVec;
    llvm::SmallDenseMap<llvm::AllocaInst *, llvm::SmallVector<llvm::IntrinsicInst *>> mAILifeTimeStart;
};