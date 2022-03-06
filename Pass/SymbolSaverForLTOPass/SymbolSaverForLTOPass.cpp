#include "llvm/Pass.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "SymbolSaverForLTO.hpp"

using namespace llvm;

namespace
{
    struct SymbolSaverForLTOPass : public ModulePass
    {
        static char ID;
        SymbolSaverForLTOPass() : ModulePass(ID) {}

        bool runOnModule(Module &M) override
        {
            // errs() << "[SymbolSaverForLTOPass] " << M.getName().str() << "\n";
            SymbolSaverForLTO saver(M);
            return saver.runOnModule(M);
        }
    };
}

char SymbolSaverForLTOPass::ID = 0;
static RegisterPass<SymbolSaverForLTOPass> X("SymbolSaverForLTOPass", "SymbolSaverForLTOPass", false, false);

static RegisterStandardPasses l0_register_std_pass(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SymbolSaverForLTOPass()); });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SymbolSaverForLTOPass()); });
