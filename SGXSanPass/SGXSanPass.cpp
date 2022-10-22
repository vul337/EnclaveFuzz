#include "llvm/Analysis/CFLSteensAliasAnalysis.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"

#include "AddressSanitizer.h"
#include "AdjustUSP.hpp"
#include "SensitiveLeakSan.hpp"

using namespace llvm;

static cl::opt<bool>
    ClEnableSensitiveLeakSan("enable-sensitive-leak-san",
                             cl::desc("whether enable sensitive leak santizer"),
                             cl::Hidden, cl::init(false));

namespace {
// New PM implementation
struct SGXSanNewPass : PassInfoMixin<SGXSanNewPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    bool Changed = false;

    // std::error_code EC;
    // raw_fd_stream f(M.getName().str() + ".dump", EC);
    // M.print(f, nullptr);

    // run SensitiveLeakSan Pass
    if (ClEnableSensitiveLeakSan) {
      dbgs() << "<< SensitiveLeakSan: " << M.getName().str() << " >>\n";
      SensitiveLeakSan SLSan(M, MAM.getResult<CFLSteensAA>(M));
      Changed |= SLSan.runOnModule();
    }

    dbgs() << "<< SGXSanPass: " << M.getName().str() << " >>\n";
    GlobalsMetadata GlobalsMD = GlobalsMetadata(M);
    const TargetLibraryInfo *TLI = &MAM.getResult<TargetLibraryAnalysis>(M);
    AddressSanitizer ASan(M, &GlobalsMD, false, false, true,
                          AsanDetectStackUseAfterReturnMode::Never);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      if (F.getName().startswith("sgxsan_ocall_") ||
          F.getName().startswith("sgx_sgxsan_ecall_") ||
          F.getName().startswith("fuzzer_ocall_") ||
          F.getName().startswith("sgx_fuzzer_ecall_")) {
        Changed |= adjustUntrustedSPRegisterAtOcallAllocAndFree(F);
        // Since we have monitored malloc-serial function, (linkonce_odr type
        // function) in library which will check shadowbyte whether instrumented
        // or not is not necessary. don't call instrumentFunction()
      } else {
        // hook sgx-specifical callee, normal asan, elrange check, Out-Addr
        // Whitelist check, GlobalPropageteWhitelist Sensitive area check,
        // Whitelist fill, Whitelist (De)Active, poison etc.
        Changed |= ASan.instrumentFunction(F, TLI);
      }
    }
    ModuleAddressSanitizer MASan(M, &GlobalsMD);
    Changed |= MASan.instrumentModule(M);

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  static bool isRequired() { return true; }
};

// Legacy PM implementation
struct SGXSanPass : public ModulePass {
  static char ID;
  SGXSanPass() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    if (ClEnableSensitiveLeakSan) {
      AU.addRequired<CFLSteensAAWrapperPass>();
    }
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }

  bool runOnModule(Module &M) override {
    bool Changed = false;

    // std::error_code EC;
    // raw_fd_stream f(M.getName().str() + ".dump", EC);
    // M.print(f, nullptr);

    // run SensitiveLeakSan Pass
    if (ClEnableSensitiveLeakSan) {
      dbgs() << "<< SensitiveLeakSan: " << M.getName().str() << " >>\n";
      CFLSteensAAResult &AAResult =
          getAnalysis<CFLSteensAAWrapperPass>().getResult();
      SensitiveLeakSan SLSan(M, AAResult);
      Changed |= SLSan.runOnModule();
    }

    dbgs() << "<< SGXSanPass: " << M.getName().str() << " >>\n";
    GlobalsMetadata GlobalsMD = GlobalsMetadata(M);
    AddressSanitizer ASan(M, &GlobalsMD, false, false, true,
                          AsanDetectStackUseAfterReturnMode::Never);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      if (F.getName().startswith("sgxsan_ocall_") ||
          F.getName().startswith("sgx_sgxsan_ecall_") ||
          F.getName().startswith("fuzzer_ocall_") ||
          F.getName().startswith("sgx_fuzzer_ecall_")) {
        Changed |= adjustUntrustedSPRegisterAtOcallAllocAndFree(F);
        // Since we have monitored malloc-serial function, (linkonce_odr type
        // function) in library which will check shadowbyte whether instrumented
        // or not is not necessary. don't call instrumentFunction()
      } else {
        const TargetLibraryInfo *TLI =
            &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
        // hook sgx-specifical callee, normal asan, elrange check, Out-Addr
        // Whitelist check, GlobalPropageteWhitelist Sensitive area check,
        // Whitelist fill, Whitelist (De)Active, poison etc.
        Changed |= ASan.instrumentFunction(F, TLI);
      }
    }
    ModuleAddressSanitizer MASan(M, &GlobalsMD);
    Changed |= MASan.instrumentModule(M);
    return Changed;
  }
}; // end of struct SGXSanPass
} // end of anonymous namespace

// New Pass Manager
llvm::PassPluginLibraryInfo getSGXSanNewPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "SGXSanNewPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // now only llvm-15 support register new lto pass
            // PB.registerFullLinkTimeOptimizationEarlyEPCallback(
            //     [](ModulePassManager &MPM, PassBuilder::OptimizationLevel)
            //     {
            //         MPM.addPass(SGXSanNewPass());
            //     });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getSGXSanNewPassPluginInfo();
}

// Old Pass Manager
char SGXSanPass::ID = 0;
static RegisterPass<SGXSanPass>
    register_sgxsan_pass("SGXSanPass", "SGXSanPass",
                         false /* Only looks at CFG */,
                         false /* Analysis Pass */);

static RegisterStandardPasses lto_register_std_pass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanPass());
    });

static RegisterStandardPasses l0_register_std_pass(
    /* EP_EarlyAsPossible can only be used in
       FunctionPass(https://lists.llvm.org/pipermail/llvm-dev/2018-June/123987.html)
     */
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanPass());
    });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanPass());
    });