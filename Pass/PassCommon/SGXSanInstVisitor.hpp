#pragma once

#include <unordered_map>

#include "llvm/IR/InstVisitor.h"
#include "llvm/Analysis/ValueTracking.h"

namespace llvm
{
    class SGXSanInstVisitor : public InstVisitor<SGXSanInstVisitor>
    {
    public:
        SGXSanInstVisitor(BasicBlock &BB);
        SGXSanInstVisitor(Function &F);
        SGXSanInstVisitor(Module &M);
        void visitReturnInst(ReturnInst &RI);
        void visitResumeInst(ResumeInst &RI);
        void visitCleanupReturnInst(CleanupReturnInst &CRI);
        void visitCallInst(CallInst &CI);
        void visitIntrinsicInst(IntrinsicInst &II);
        SmallVector<ReturnInst *> getRetInstVec();
        SmallVector<Instruction *> getBroadRetInstVec();
        SmallVector<CallInst *> getCallInstVec();
        std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>> getAILifeTimeStart();

    private:
        SmallVector<ReturnInst *> mReturnInstVec;
        SmallVector<Instruction *> mBroadReturnInstVec;
        SmallVector<CallInst *> mCallInstVec;
        std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>> mAILifeTimeStart;
    };

    class InstVisitorCache
    {
    public:
        static SGXSanInstVisitor *getInstVisitor(Module *M);
        static SGXSanInstVisitor *getInstVisitor(Function *F);

    private:
        ~InstVisitorCache();

        static std::unordered_map<Module *, SGXSanInstVisitor *> SGXSanInstVisitorModuleMap;
        static std::unordered_map<Function *, SGXSanInstVisitor *> SGXSanInstVisitorFuncMap;
    };
}