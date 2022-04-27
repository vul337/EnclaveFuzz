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
        void visitCallInst(CallInst &CI);
        void visitIntrinsicInst(IntrinsicInst &II);
        void getRetInstVec(SmallVector<ReturnInst *> &ReturnInstVec);
        void getCallInstVec(SmallVector<CallInst *> &CallInstVec);
        void getAILifeTimeStart(std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>> &AILifeTimeStart);

    private:
        SmallVector<ReturnInst *> mReturnInstVec;
        SmallVector<CallInst *> mCallInstVec;
        std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>> mAILifeTimeStart;
    };

    class InstVisitorCache
    {
    public:
        static void getInstVisitor(Module *M, SGXSanInstVisitor *&instVisitor);
        static void getInstVisitor(Function *F, SGXSanInstVisitor *&instVisitor);

    private:
        ~InstVisitorCache();

        static std::unordered_map<Module *, SGXSanInstVisitor *> SGXSanInstVisitorModuleMap;
        static std::unordered_map<Function *, SGXSanInstVisitor *> SGXSanInstVisitorFuncMap;
    };
}