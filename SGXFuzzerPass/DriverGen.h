#pragma once

#include "nlohmann/json.hpp"
#include "llvm/IR/Module.h"

namespace llvm {
class DriverGenerator {
public:
  void initialize(Module &M);
  // propagate [in]/[out]/[user_check] to it's element
  void inheritDirectionAttr(nlohmann::json::json_pointer jsonPtr,
                            size_t field_index);
  nlohmann::json::json_pointer getRootPtr(nlohmann::json::json_pointer jsonPtr);
  bool isECallPtr(nlohmann::json::json_pointer jsonPtr);
  bool whetherFeedRandom(nlohmann::json::json_pointer jsonPtr);
  void dump(nlohmann::json js, nlohmann::json::json_pointer jsonPtr);
  void dataCopy(Value *dstPtr, Value *srcPtr, Type *type, Instruction *insertPt,
                Value *arrCnt = nullptr);
  GlobalVariable *CreateZeroInitizerGlobal(StringRef Name, Type *Ty);
  Value *createParamContent(SmallVector<Type *> types,
                            nlohmann::json::json_pointer jsonPtr,
                            std::map<uint64_t, Value *> *paramPtrs,
                            Instruction *insertPt);
  void fillAtOnce(Value *dstPtr, nlohmann::json::json_pointer jsonPtr,
                  Instruction *insertPt, Type *type = nullptr,
                  Value *arrCnt = nullptr, bool isOcall = false);
  bool hasPointerElement(Type *type);
  bool _hasPointerElement(Type *type, size_t level = 0);
  Function *createEcallFuzzWrapperFunc(std::string ecallName);
  // create content for ocall [out] pointer parameters
  void saveCreatedInput2OCallPtrParam(Function *ocallFunc,
                                      Instruction *insertPt);
  void createOcallFunc(std::string ocallName);
  void passStaticAnalysisResultToRuntime(
      SmallVector<Constant *> &ecallFuzzWrapperFuncs);
  bool runOnModule(Module &M);
  void updateFuzzBufferTotalSize();
  size_t _updateFuzzBufferTotalSize(nlohmann::json::json_pointer ptr);

private:
  FunctionCallee getIndexOfEcallToBeFuzzed, getFuzzDataPtr, getUserCheckCount,
      _strlen, _wcslen, whetherSetNullPointer;
  Module *M = nullptr;
  LLVMContext *C = nullptr;
  nlohmann::json edlJson, fuzzBufferJson;
  std::map<Type *, bool> typeHasPointerMap;
};
} // namespace llvm