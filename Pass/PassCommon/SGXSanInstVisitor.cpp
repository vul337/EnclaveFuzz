#include "SGXSanInstVisitor.hpp"

using namespace llvm;

VisitInfo &SGXSanInstVisitor::visitBasicBlock(BasicBlock &BB)
{
    if (BasicBlockVisitInfoMap.count(&BB) == 0)
    {
        VisitInfo &info = BasicBlockVisitInfoMap[&BB];
        for (auto &I : BB)
        {
            if (auto RetI = dyn_cast<ReturnInst>(&I))
            {
                info.ReturnInstVec.push_back(RetI);
                info.BroadReturnInstVec.push_back(RetI);
            }
            else if (auto ResumeI = dyn_cast<ResumeInst>(&I))
            {
                info.BroadReturnInstVec.push_back(ResumeI);
            }
            else if (auto CleanupReturnI = dyn_cast<CleanupReturnInst>(&I))
            {
                info.BroadReturnInstVec.push_back(CleanupReturnI);
            }
            else if (auto CallI = dyn_cast<CallInst>(&I))
            {
                info.CallInstVec.push_back(CallI);

                auto IntrinsicI = dyn_cast<IntrinsicInst>(CallI);
                if (IntrinsicI && IntrinsicI->getIntrinsicID() == Intrinsic::lifetime_start)
                {
                    // it's a lifetime_start IntrinsicInst
                    AllocaInst *AllocaI = findAllocaForValue(IntrinsicI->getArgOperand(1), true);
                    if (AllocaI)
                        info.AILifeTimeStart[AllocaI].push_back(IntrinsicI);
                }
            }
        }
    }
    return BasicBlockVisitInfoMap[&BB];
}

VisitInfo &SGXSanInstVisitor::visitFunction(Function &F)
{
    if (FunctionVisitInfoMap.count(&F) == 0)
    {
        auto &FVisitInfo = FunctionVisitInfoMap[&F];
        for (auto &BB : F)
        {
            auto &BBVisitInfo = visitBasicBlock(BB);
            for (auto pair : BBVisitInfo.AILifeTimeStart)
            {
                FVisitInfo.AILifeTimeStart[pair.first].append(pair.second);
            }
            FVisitInfo.BroadReturnInstVec.append(BBVisitInfo.BroadReturnInstVec);
            FVisitInfo.ReturnInstVec.append(BBVisitInfo.ReturnInstVec);
            FVisitInfo.CallInstVec.append(BBVisitInfo.CallInstVec);
        }
    }
    return FunctionVisitInfoMap[&F];
}

VisitInfo &SGXSanInstVisitor::visitModule(Module &M)
{
    if (ModuleVisitInfoMap.count(&M) == 0)
    {
        auto &MVisitInfo = ModuleVisitInfoMap[&M];
        for (auto &F : M)
        {
            auto &FVisitInfo = visitFunction(F);
            for (auto pair : FVisitInfo.AILifeTimeStart)
            {
                MVisitInfo.AILifeTimeStart[pair.first].append(pair.second);
            }
            MVisitInfo.BroadReturnInstVec.append(FVisitInfo.BroadReturnInstVec);
            MVisitInfo.ReturnInstVec.append(FVisitInfo.ReturnInstVec);
            MVisitInfo.CallInstVec.append(FVisitInfo.CallInstVec);
        }
    }
    return ModuleVisitInfoMap[&M];
}

std::map<BasicBlock *, VisitInfo> SGXSanInstVisitor::BasicBlockVisitInfoMap;
std::map<Function *, VisitInfo> SGXSanInstVisitor::FunctionVisitInfoMap;
std::map<Module *, VisitInfo> SGXSanInstVisitor::ModuleVisitInfoMap;
