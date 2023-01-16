#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <boost/algorithm/string.hpp>

using namespace llvm;

namespace {
struct GetOCallTablePass : public ModulePass {
  static char ID;
  GetOCallTablePass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    GlobalVariable *OCallTableGV = nullptr;
    for (auto &GV : M.globals()) {
      if (GV.getName().contains("ocall_table_")) {
        OCallTableGV = &GV;
      }
    }
    if (OCallTableGV) {
      dbgs() << "== Add GetOCallTableAddr in " << M.getName()
             << " to get internal " << OCallTableGV->getName() << " ==\n";
      // Define a function that return address of ocall table
      FunctionCallee GetOCallTableAddrCallee = M.getOrInsertFunction(
          "GetOCallTableAddr", Type::getInt8PtrTy(M.getContext()));
      Function *GetOCallTableAddr =
          cast<Function>(GetOCallTableAddrCallee.getCallee());
      auto EntryBB = BasicBlock::Create(M.getContext(), "", GetOCallTableAddr);
      IRBuilder<> IRB(EntryBB);
      IRB.CreateRet(IRB.CreatePointerCast(OCallTableGV, IRB.getInt8PtrTy()));
      return true;
    } else {
      return false;
    }
  }
};
} // namespace

char GetOCallTablePass::ID = 0;
static RegisterPass<GetOCallTablePass>
    X("GetOCallTablePass", "Create function GetOCallTableAddr in UBridge");

#define REGISTER_PASS(name, extension_point)                                   \
  static RegisterStandardPasses name(                                          \
      extension_point,                                                         \
      [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {     \
        PM.add(new GetOCallTablePass());                                       \
      });

REGISTER_PASS(l0_register_std_pass, PassManagerBuilder::EP_EnabledOnOptLevel0)
REGISTER_PASS(moe_register_std_pass,
              PassManagerBuilder::EP_ModuleOptimizerEarly)
