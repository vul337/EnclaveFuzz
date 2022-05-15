#include "SGXSanInstVisitor.hpp"

using namespace llvm;

SGXSanInstVisitor::SGXSanInstVisitor(BasicBlock &BB)
{
    visit(BB);
}

SGXSanInstVisitor::SGXSanInstVisitor(Function &F)
{
    visit(F);
}

SGXSanInstVisitor::SGXSanInstVisitor(Module &M)
{
    visit(M);
}

void SGXSanInstVisitor::visitReturnInst(ReturnInst &RI)
{
    mReturnInstVec.push_back(&RI);
    mBroadReturnInstVec.push_back(&RI);
}

void SGXSanInstVisitor::visitResumeInst(ResumeInst &RI)
{
    mBroadReturnInstVec.push_back(&RI);
}

void SGXSanInstVisitor::visitCleanupReturnInst(CleanupReturnInst &CRI)
{
    mBroadReturnInstVec.push_back(&CRI);
}

void SGXSanInstVisitor::visitCallInst(CallInst &CI)
{
    mCallInstVec.push_back(&CI);
}

void SGXSanInstVisitor::visitIntrinsicInst(IntrinsicInst &II)
{
    // because `IntrinsicInst` is a derived class of `CallInst`,
    // `visitCallInst` will not catch this `II` any more
    mCallInstVec.push_back(cast<CallInst>(&II));

    auto ID = II.getIntrinsicID();
    if (ID == Intrinsic::lifetime_start)
    {
        AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
        assert(AI);
        mAILifeTimeStart[AI].push_back(&II);
    }
}

SmallVector<ReturnInst *> SGXSanInstVisitor::getRetInstVec()
{
    return mReturnInstVec;
}

SmallVector<Instruction *> SGXSanInstVisitor::getBroadRetInstVec()
{
    return mBroadReturnInstVec;
}

SmallVector<CallInst *> SGXSanInstVisitor::getCallInstVec()
{
    return mCallInstVec;
}

std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>> SGXSanInstVisitor::getAILifeTimeStart()
{
    return mAILifeTimeStart;
}

SGXSanInstVisitor *InstVisitorCache::getInstVisitor(Module *M)
{
    auto it = SGXSanInstVisitorModuleMap.find(M);
    if (it != SGXSanInstVisitorModuleMap.end())
    {
        return it->second;
    }
    else
    {
        SGXSanInstVisitor *moduleInstVisitor = new SGXSanInstVisitor(*M);
        SGXSanInstVisitorModuleMap[M] = moduleInstVisitor;
        return moduleInstVisitor;
    }
}

SGXSanInstVisitor *InstVisitorCache::getInstVisitor(Function *F)
{
    auto it = SGXSanInstVisitorFuncMap.find(F);
    if (it != SGXSanInstVisitorFuncMap.end())
    {
        return it->second;
    }
    else
    {
        SGXSanInstVisitor *funcInstVisitor = new SGXSanInstVisitor(*F);
        SGXSanInstVisitorFuncMap[F] = funcInstVisitor;
        return funcInstVisitor;
    }
}

InstVisitorCache::~InstVisitorCache()
{
    for (auto &it : SGXSanInstVisitorModuleMap)
    {
        delete it.second;
    }
    for (auto &it : SGXSanInstVisitorFuncMap)
    {
        delete it.second;
    }
}

std::unordered_map<Module *, SGXSanInstVisitor *> InstVisitorCache::SGXSanInstVisitorModuleMap;
std::unordered_map<Function *, SGXSanInstVisitor *> InstVisitorCache::SGXSanInstVisitorFuncMap;
