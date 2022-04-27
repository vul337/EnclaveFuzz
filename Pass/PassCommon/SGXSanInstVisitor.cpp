#include "SGXSanInstVisitor.hpp"

using namespace llvm;

SGXSanInstVisitor::SGXSanInstVisitor(llvm::BasicBlock &BB)
{
    visit(BB);
}

SGXSanInstVisitor::SGXSanInstVisitor(llvm::Function &F)
{
    visit(F);
}

SGXSanInstVisitor::SGXSanInstVisitor(llvm::Module &M)
{
    visit(M);
}

void SGXSanInstVisitor::visitReturnInst(llvm::ReturnInst &RI)
{
    mReturnInstVec.push_back(&RI);
}

void SGXSanInstVisitor::visitCallInst(llvm::CallInst &CI)
{
    mCallInstVec.push_back(&CI);
}

void SGXSanInstVisitor::visitIntrinsicInst(llvm::IntrinsicInst &II)
{
    // because `IntrinsicInst` is a derived class of `CallInst`,
    // `visitCallInst` will not catch this `II` any more
    mCallInstVec.push_back(llvm::cast<llvm::CallInst>(&II));

    auto ID = II.getIntrinsicID();
    if (ID == llvm::Intrinsic::lifetime_start)
    {
        llvm::AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
        assert(AI);
        mAILifeTimeStart[AI].push_back(&II);
    }
}

void SGXSanInstVisitor::getRetInstVec(llvm::SmallVector<llvm::ReturnInst *> &ReturnInstVec)
{
    ReturnInstVec = mReturnInstVec;
}

void SGXSanInstVisitor::getCallInstVec(llvm::SmallVector<llvm::CallInst *> &CallInstVec)
{
    CallInstVec = mCallInstVec;
}

void SGXSanInstVisitor::getAILifeTimeStart(std::unordered_map<llvm::AllocaInst *, llvm::SmallVector<llvm::IntrinsicInst *>> &AILifeTimeStart)
{
    AILifeTimeStart = mAILifeTimeStart;
}

void InstVisitorCache::getInstVisitor(Module *M, SGXSanInstVisitor *&instVisitor)
{
    auto it = SGXSanInstVisitorModuleMap.find(M);
    if (it != SGXSanInstVisitorModuleMap.end())
    {
        instVisitor = it->second;
    }
    else
    {
        SGXSanInstVisitor *moduleInstVisitor = new SGXSanInstVisitor(*M);
        SGXSanInstVisitorModuleMap[M] = moduleInstVisitor;
        instVisitor = moduleInstVisitor;
    }
}

void InstVisitorCache::getInstVisitor(Function *F, SGXSanInstVisitor *&instVisitor)
{
    auto it = SGXSanInstVisitorFuncMap.find(F);
    if (it != SGXSanInstVisitorFuncMap.end())
    {
        instVisitor = it->second;
    }
    else
    {
        SGXSanInstVisitor *funcInstVisitor = new SGXSanInstVisitor(*F);
        SGXSanInstVisitorFuncMap[F] = funcInstVisitor;
        instVisitor = funcInstVisitor;
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
