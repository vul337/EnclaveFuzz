#pragma once

#include <unordered_map>

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/InstVisitor.h"

namespace llvm {
struct VisitInfo {
  SmallVector<ReturnInst *> ReturnInstVec;
  SmallVector<Instruction *> BroadReturnInstVec;
  SmallVector<CallInst *> CallInstVec;
  std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>>
      AILifeTimeStart;
};

class SGXSanInstVisitor {
public:
  static VisitInfo &visitBasicBlock(BasicBlock &BB);
  static VisitInfo &visitFunction(Function &F);
  static VisitInfo &visitModule(Module &M);

private:
  static std::map<BasicBlock *, VisitInfo> BasicBlockVisitInfoMap;
  static std::map<Function *, VisitInfo> FunctionVisitInfoMap;
  static std::map<Module *, VisitInfo> ModuleVisitInfoMap;
};
} // namespace llvm