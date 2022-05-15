#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "AdjustUSP.hpp"
#include "PassCommon.hpp"
#include "SGXSanInstVisitor.hpp"
#include <assert.h>

using namespace llvm;

void adjustUntrustedSPRegisterAtOcallAllocAndFree(Function &F)
{
    // initialize
    Module *M = F.getParent();
    IRBuilder<> IRB(M->getContext());
    FunctionCallee SetUSP = M->getOrInsertFunction("set_untrust_sp", IRB.getVoidTy(), IRB.getInt64Ty());
    FunctionCallee GetUSP = M->getOrInsertFunction("get_untrust_sp", IRB.getInt64Ty());

    // get interesting callinst
    SmallVector<CallInst *> OcallocVec, OcfreeVec,
        CallInstVec = InstVisitorCache::getInstVisitor(&F)->getCallInstVec();
    for (auto CI : CallInstVec)
    {
        StringRef callee_name = getDirectCalleeName(CI);
        if (callee_name == "sgx_ocalloc")
        {
            OcallocVec.push_back(CI);
        }
        else if (callee_name == "sgx_ocfree")
        {
            OcfreeVec.push_back(CI);
        }
    }

    // instrument
    IRB.SetInsertPoint(&F.getEntryBlock().getInstList().front());
    Value *usp = IRB.CreateAlloca(IRB.getInt64Ty());
    for (auto CI : OcallocVec)
    {
        IRB.SetInsertPoint(CI);
        IRB.CreateStore(IRB.CreateCall(GetUSP), usp);
    }
    for (auto CI : OcfreeVec)
    {
        IRB.SetInsertPoint(CI->getNextNode());
        IRB.CreateCall(SetUSP, IRB.CreateLoad(usp));
    }
}