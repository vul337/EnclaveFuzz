#include "DriverGen.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

using namespace llvm;

/// Pass Register
class SGXFuzzerPass : public ModulePass {
public:
  SGXFuzzerPass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    // run DriverGenerator
    dbgs() << "== DriverGenerator: " << M.getName() << " ==\n";
    DriverGenerator gen;
    return gen.runOnModule(M);
  }

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