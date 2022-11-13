#include "nlohmann/json.hpp"
#include "llvm/ADT/Triple.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Transforms/Instrumentation.h"

namespace llvm {
class ModuleSanitizerCoverage {
public:
  ModuleSanitizerCoverage(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions(),
      const SpecialCaseList *Allowlist = nullptr,
      const SpecialCaseList *Blocklist = nullptr);
  bool instrumentModule(
      Module &M, function_ref<const DominatorTree *(Function &F)> DTCallback,
      function_ref<const PostDominatorTree *(Function &F)> PDTCallback,
      bool IsModuleAtEnclave = false);

private:
  void instrumentFunction(
      Function &F, function_ref<const DominatorTree *(Function &F)> DTCallback,
      function_ref<const PostDominatorTree *(Function &F)> PDTCallback);
  void InjectCoverageForIndirectCalls(Function &F,
                                      ArrayRef<Instruction *> IndirCalls);
  void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
  void InjectTraceForDiv(Function &F,
                         ArrayRef<BinaryOperator *> DivTraceTargets);
  void InjectTraceForGep(Function &F,
                         ArrayRef<GetElementPtrInst *> GepTraceTargets);
  void InjectTraceForSwitch(Function &F,
                            ArrayRef<Instruction *> SwitchTraceTargets);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                      bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                       const char *InitFunctionName, Type *Ty,
                                       const char *Section);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I);

  std::string getSectionName(const std::string &Section) const;
  std::string getSectionStart(const std::string &Section) const;
  std::string getSectionEnd(const std::string &Section) const;
  FunctionCallee SanCovTracePCIndir;
  FunctionCallee SanCovTracePC, SanCovTracePCGuard;
  FunctionCallee SanCovTraceCmpFunction[4];
  FunctionCallee SanCovTraceConstCmpFunction[4];
  FunctionCallee SanCovTraceDivFunction[2];
  FunctionCallee SanCovTraceGepFunction;
  FunctionCallee SanCovTraceSwitchFunction;
  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;
  Module *CurModule;
  std::string CurModuleUniqueId;
  Triple TargetTriple;
  LLVMContext *C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;       // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray; // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;        // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;         // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  const SpecialCaseList *Allowlist;
  const SpecialCaseList *Blocklist;

  bool CurModuleAtEnclave;
  GlobalVariable *WholeEnclave8bitCounterArrayAddr;
  size_t WholeEnclave8bitCounterArraySize;
  nlohmann::json *CurInstrumentJson;
};
} // namespace llvm