#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "SensitiveLeakSan.hpp"

using namespace llvm;

namespace
{
    struct SensitiveLeakSanPass : public ModulePass
    {
        static char ID;
        SensitiveLeakSanPass() : ModulePass(ID) {}

        bool runOnModule(Module &M) override
        {
            SensitiveLeakSan SLSan(M);
            return SLSan.runOnModule();
        };
    }; // end of struct SGXSanPass
}

char SensitiveLeakSanPass::ID = 0;
static RegisterPass<SensitiveLeakSanPass> register_SensitiveLeakSanPass(
    "SensitiveLeakSanPass", "SensitiveLeakSanPass", false, false);

static RegisterStandardPasses lto_register_std_pass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM)
    { PM.add(new SensitiveLeakSanPass()); });

static RegisterStandardPasses l0_register_std_pass(
    /* EP_EarlyAsPossible can only be used in FunctionPass(https://lists.llvm.org/pipermail/llvm-dev/2018-June/123987.html) */
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SensitiveLeakSanPass()); });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SensitiveLeakSanPass()); });
