#pragma once

#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CFLSteensAliasAnalysis.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#include "DDA/ContextDDA.h"
#include "DDA/DDAClient.h"
#include "Graphs/SVFG.h"
#include "MemoryModel/ConditionalPT.h"
#include "SABER/LeakChecker.h"
#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/DPItem.h"
#include "Util/config.h"
#include "WPA/Andersen.h"

#include "AddressSanitizer.h"
#include "PassUtil.h"

#include <regex>
#include <unordered_map>
#include <unordered_set>

namespace llvm {
enum SensitiveLevel { NOT_SENSITIVE = 0, MAY_BE_SENSITIVE, IS_SENSITIVE };

class SensitiveLeakSanitizer {
public:
  SensitiveLeakSanitizer(Module &M);
  ~SensitiveLeakSanitizer();
  void initSVF();
  bool runOnModule(Module &M, CFLSteensAAResult &AAResult);
  void collectAndPoisonSensitiveObj();
  void doVFA(Value *work);
  void pushSensitiveObj(Value *annotatedVar);
  void
  poisonSensitiveStackOrHeapObj(SVF::ObjVar *objPN,
                                std::pair<bool *, size_t> *sensitiveIndicator);
  Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
  Value *memPtrToShadowPtr(Value *memPtr, IRBuilder<> &IRB);

  int getCallInstOperandPosition(CallInst *CI, Value *oprend,
                                 bool rawOperand = false);
  SmallVector<Function *> getDirectAndIndirectCalledFunction(CallInst *CI);
  Instruction *findInstByName(Function *F, std::string InstName);
  std::unordered_set<SVF::ValVar *> getRevPtValPNs(SVF::ObjVar *obj);
  void addAndPoisonSensitiveObj(
      SVF::ObjVar *obj, std::pair<bool *, size_t> *shadowBytesPair = nullptr);
  Value *RoundUpUDiv(IRBuilder<> &IRB, Value *size, uint64_t dividend);
  uint64_t RoundUpUDiv(uint64_t dividend, uint64_t divisor);
  void addPtObj2WorkList(Value *ptr);
  void setNoSanitizeMetadata(Instruction *I);
  void propagateShadowInMemTransfer(CallInst *CI, Instruction *insertPoint,
                                    Value *destPtr, Value *srcPtr,
                                    Value *dstSize, Value *copyCnt);
  std::unordered_set<SVF::ObjVar *> getNonPtrObjPNs(SVF::ObjVar *objPN);
  std::unordered_set<SVF::ObjVar *> getNonPtrObjPNs(Value *value);
  Value *instrumentPoisonCheck(Value *src);
  Value *isPtrPoisoned(Instruction *insertPoint, Value *ptr,
                       Value *size = nullptr);
  static int getPointerLevel(const Value *ptr);
  void PoisonCIOperand(Value *src, Value *isPoisoned, CallInst *CI,
                       int operandPosition);
  void PoisonSI(Value *src, Value *isPoisoned, StoreInst *SI);
  void PoisonRetShadow(Value *src, Value *isPoisoned, ReturnInst *calleeRI);
  void PoisonMemsetDst(Value *src, Value *isSrcPoisoned, CallInst *MSI,
                       Value *dstPtr, Value *setSize);
  void propagateShadow(Value *src);
  static bool isAnnotationIntrinsic(CallInst *CI);
  static std::string extractAnnotation(Value *annotationStrVal);
  static bool isSecureVersionMemTransferCI(CallInst *CI);
  static bool ContainWord(StringRef str, const std::string word);
  static bool ContainWordExactly(StringRef str, const std::string word);
  static bool isEncryptionFunction(Function *F);
  void RTPoisonSensitiveGV();
  void initializeCallbacks();
  // only process `AllocInst` stack object
  void ShallowUnpoisonStackObj(Value *stackObject);
  void ShallowUnpoisonStackObj(SVF::ObjVar *objPN);
  Value *getStackOrHeapInstObjSize(Instruction *objI);
  void dumpPts(SVF::SVFVar *PN);
  void dumpRevPts(SVF::SVFVar *PN);
  // instrument push/pop_thread_func_arg_shadow_stack around CI
  void pushAndPopArgShadowStack(CallInst *CI);
  static std::string toString(SVF::SVFVar *PN);
  static std::string toString(Value *val);
  static void dump(SVF::SVFVar *PN);
  void dump(SVF::NodeID nodeID);
  static void dump(Value *val);
  void RTPrintSrc(IRBuilder<> &IRB, Value *src);
  void collectHeapAllocators();
  void collectHeapAllocatorGlobalPtrs();
  bool isHeapAllocatorWrapper(Function &F);
  bool hasObjectNode(Value *val);
  void analyseModuleMetadata();
  void analyseDIType(DIType *type);
  DICompositeType *getDICompositeType(StructType *structTy);
  StructType *getStructTypeOfHeapObj(SVF::ObjVar *heapObj);
  bool isSensitive(StringRef str);
  bool mayBeSensitive(StringRef str);
  /// \retval 1) \c true: some struct member is sensitive
  bool getSensitiveIndicator(DICompositeType *compositeTy,
                             std::pair<bool *, size_t> *sensitiveIndicator,
                             size_t offset);
  /// \retval 1) \c true: \p ty is a structure and some member of this structure
  /// is sensitive
  bool getSubfieldSensitiveIndicator(
      DIType *ty, std::pair<bool *, size_t> *sensitiveIndicator, size_t offset);
  void
  ShallowPoisonAlignedObject(Value *objPtr, Value *objSize, IRBuilder<> &IRB,
                             std::pair<bool *, size_t> *sensitiveIndicator);
  SensitiveLevel getSensitiveLevel(StringRef str);
  StringRef getObjMeaningfulName(SVF::ObjVar *objPN);
  static bool isTBridgeFunc(Function &F);
  // update SVF's ExtAPI.json
  void updateSVFExtAPI();

  /// \retval 1) If \p value is just an object, then only this ObjVar will
  /// return \retval 2) Otherwise, objects this \p value point to will return
  std::unordered_set<SVF::ObjVar *> getTargetObj(Value *value);

  Value *CheckIsPtrInEnclave(Value *ptr, Value *size, Instruction *insertPt,
                             const DebugLoc *dbgLoc);

private:
  std::unordered_set<SVF::ObjVar *> SensitiveObjs, WorkList, ProcessedList;
  std::unordered_set<Value *> poisonedInst;
  std::unordered_set<AllocaInst *> shallowUnpoisonedStackObjs;
  std::unordered_set<CallInst *> processedMemTransferInst;
  std::unordered_map<CallInst *, std::unordered_set<int>> poisonedCI;
  std::unordered_map<Value *, Value *> poisonCheckedValues;
  GlobalVariable *SGXSanEnclaveBaseAddr = nullptr,
                 *SGXSanEnclaveSizeAddr = nullptr,
                 *ThreadFuncArgShadow = nullptr;
  FunctionCallee PoisonArg, ArgIsPoisoned, PushArgShadowStack,
      PopArgShadowStack, IsWithinEnclave, RegionIsInEnclaveAndPoisoned,
      SGXSanLog, PrintPtr, PrintArg, MallocUsableSize, PoisonSensitiveGlobal,
      ShallowPoisonShadow, MoveShallowShadow;

  Module *M = nullptr;
  LLVMContext *C = nullptr;
  Type *IntptrTy = nullptr;

  SVF::SVFModule *svfModule = nullptr;
  SVF::SVFIR *pag = nullptr;
  SVF::Andersen *ander = nullptr;
  SVF::PTACallGraph *callgraph = nullptr;
  SVF::SymbolTableInfo::ValueToIDMapTy *objSym = nullptr;

  SmallVector<Constant *> globalsToBePolluted;
  Function *PoisonSensitiveGlobalModuleCtor = nullptr;
  Constant *StrSpeicifier = nullptr;
  std::set<Function *> heapAllocators;
  std::set<GlobalVariable *> heapAllocatorGlobalPtrs;
  CFLSteensAAResult *AAResult = nullptr;
  std::unordered_set<std::string> heapAllocatorBaseNames{"malloc", "calloc",
                                                         "realloc"},
      heapAllocatorWrapperNames, heapAllocatorNames,
      plaintextKeywords = {"2encrypt", "unencrypt", "2seal",  "unseal",
                           "plain",    "secret",    "decrypt"},
      ciphertextKeywords = {"2decrypt", "undecrypt"},
      exactCiphertextKeywords = {"enc", "encrypt", "seal", "cipher"},
      inputKeywords = {"source", "input"}, exactInputKeywords = {"src", "in"},
      exactSecretKeywords = {"key", "dec"};
  std::map<std::string, DICompositeType *> DICompositeTypeMap;
  std::unordered_set<DIType *> processedDITypes;
  size_t propagateCnt = 0;
  std::string ExtAPIJsonFile;
  ShadowMapping Mapping;
};
} // namespace llvm
