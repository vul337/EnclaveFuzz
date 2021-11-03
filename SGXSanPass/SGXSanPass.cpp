#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "AddressSanitizer.hpp"

using namespace llvm;

namespace
{
    struct SGXSanPass : public FunctionPass
    {
        static char ID;
        SGXSanPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override
        {
            AddressSanitizer ASan(*F.getParent());

            return ASan.instrumentFunction(F);
        }
    }; // end of struct SGXSanPass
} // end of anonymous namespace

char SGXSanPass::ID = 0;
static RegisterPass<SGXSanPass> X("SGXSanPass", "SGXSanPass",
                                false /* Only looks at CFG */,
                                false /* Analysis Pass */);

static RegisterStandardPasses Y(
    PassManagerBuilder::EP_EarlyAsPossible,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SGXSanPass()); });