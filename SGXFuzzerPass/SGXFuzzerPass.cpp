#include "DriverGen.h"
#include "SanitizerCoverage.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

using namespace llvm;

static cl::opt<bool> ClAtEnclave(
    "at-enclave",
    cl::desc(
        "If true, at Enclave side, increments 8-bit counter for every edge. If "
        "false, at app side, prepare coverage map for sgx enclave."),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClEnableEnclaveTesterGenerator(
    "enable-harness",
    cl::desc("Auto generate enclave test function (Only when at app side)"),
    cl::Hidden, cl::init(false));

/// Pass Register
class SGXFuzzerPass : public ModulePass {
public:
  SGXFuzzerPass() : ModulePass(ID) {}

#ifdef KAFL_FUZZER
  bool runOnModule(Module &M) override {
    // run DriverGenerator
    dbgs() << "== DriverGenerator: " << M.getName() << " ==\n";
    DriverGenerator gen;
    return gen.runOnModule(M);
  }
#else
  bool runOnModule(Module &M) override {
    bool changed = false;
    if (not ClAtEnclave && ClEnableEnclaveTesterGenerator) {
      // run DriverGenerator
      dbgs() << "== DriverGenerator: " << M.getName() << " ==\n";
      DriverGenerator gen;
      changed |= gen.runOnModule(M);
    }

    ModuleSanitizerCoverage ModuleSancov;
    auto DTCallback = [this](Function &F) -> const DominatorTree * {
      return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
    };
    auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {
      return &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                  .getPostDomTree();
    };
    changed |=
        ModuleSancov.instrumentModule(M, DTCallback, PDTCallback, ClAtEnclave);
    return changed;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();
  }
#endif

  static char ID; // Pass identification, replacement for typeid
};

char SGXFuzzerPass::ID = 0;

static RegisterPass<SGXFuzzerPass>
    X("SGXFuzzerPass", "Genterate ECall caller and OCall at app side");

static RegisterStandardPasses Y_MOE(PassManagerBuilder::EP_ModuleOptimizerEarly,
                                    [](const PassManagerBuilder &Builder,
                                       legacy::PassManagerBase &PM) {
                                      PM.add(new SGXFuzzerPass());
                                    });

static RegisterStandardPasses Y_O0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                                   [](const PassManagerBuilder &Builder,
                                      legacy::PassManagerBase &PM) {
                                     PM.add(new SGXFuzzerPass());
                                   });