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

namespace {
struct FuncRenamePass : public ModulePass {
  static char ID;
  FuncRenamePass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
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
};
} // namespace

char FuncRenamePass::ID = 0;
static RegisterPass<FuncRenamePass> X("FuncRenamePass", "Rename Functions");