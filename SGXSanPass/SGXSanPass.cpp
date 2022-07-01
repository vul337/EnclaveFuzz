#include "AddressSanitizer.h"
#include "SensitiveLeakSanitizer.h"

using namespace llvm;

static cl::opt<bool>
    ClEnableSLSan("enable-slsan",
                  cl::desc("Whether enable Sensitive Leak Santizer or not"),
                  cl::Hidden, cl::init(false));

namespace {
struct SGXSanLegacyPass : public ModulePass {
  static char ID;
  SGXSanLegacyPass() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    if (ClEnableSLSan) {
      AU.addRequired<CFLSteensAAWrapperPass>();
    }
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }

  bool runOnModule(Module &M) override {
    bool Changed = false;

    // run SLSan Pass
    if (ClEnableSLSan) {
      dbgs() << "== SLSan Pass: " << M.getName().str() << " ==\n";
      SensitiveLeakSanitizer SLSan(M);
      Changed |= SLSan.runOnModule(
          M, getAnalysis<CFLSteensAAWrapperPass>().getResult());
    }

    // run SGXSan Pass
    dbgs() << "== SGXSan Pass: " << M.getName().str() << " ==\n";
    GlobalsMetadata GlobalsMD = GlobalsMetadata(M);
    AddressSanitizer ASan(M, &GlobalsMD, false, false, true,
                          AsanDetectStackUseAfterReturnMode::Never);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      const TargetLibraryInfo *TLI =
          &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
      Changed |= ASan.instrumentFunction(F, TLI);
    }
    ModuleAddressSanitizer MASan(M, &GlobalsMD);
    Changed |= MASan.instrumentModule(M);
    return Changed;
  }
}; // end of struct SGXSanLegacyPass
} // end of anonymous namespace

char SGXSanLegacyPass::ID = 0;

static RegisterStandardPasses register_lto_pass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });

static RegisterStandardPasses l0_register_std_pass(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });
