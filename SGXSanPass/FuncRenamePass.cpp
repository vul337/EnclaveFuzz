#include "FuncRenamePass.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <boost/algorithm/string.hpp>

using namespace llvm;

static cl::list<std::string> ClFuncRenameList("rename-func",
                                              cl::CommaSeparated);

bool RenameFuncSym(Module &M) {
  bool changed = false;
  for (auto rename : ClFuncRenameList) {
    std::vector<std::string> pair;
    boost::split(pair, rename, [](char c) { return c == '='; });
    assert(pair.size() == 2);
    std::string origName = pair[0], newName = pair[1];
    boost::trim(origName);
    boost::trim(newName);
    auto F = M.getFunction(origName);
    if (F) {
      dbgs() << "== FuncRenamePass: " << M.getName() << ": " << origName
             << " => " << newName << " ==\n";
      F->setName(newName);
      changed = true;
    }
  }
  return changed;
}

namespace {
struct FuncRenamePass : public ModulePass {
  static char ID;
  FuncRenamePass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override { return RenameFuncSym(M); }
};
} // namespace

char FuncRenamePass::ID = 0;
static RegisterPass<FuncRenamePass> X("FuncRenamePass", "Rename Functions");

#define REGISTER_PASS(name, extension_point, pass_name)                        \
  static RegisterStandardPasses name(                                          \
      extension_point,                                                         \
      [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {     \
        PM.add(new pass_name());                                               \
      });

REGISTER_PASS(l0_register_std_pass, PassManagerBuilder::EP_EnabledOnOptLevel0,
              FuncRenamePass)
REGISTER_PASS(moe_register_std_pass,
              PassManagerBuilder::EP_ModuleOptimizerEarly, FuncRenamePass)
