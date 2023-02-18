#pragma once

#include "PassUtil.h"
#include "nlohmann/json.hpp"
#include "llvm/IR/Module.h"

namespace llvm {
class DriverGenerator {
public:
  void initialize(Module &M);
  // propagate [in]/[out]/[user_check] to it's element
  void inheritDirectionAttr(nlohmann::json::json_pointer jsonPtr,
                            size_t field_index, Type *eleTy);
  bool IsOCallReturn(nlohmann::json::json_pointer jsonPtr);
  std::string RootToken(nlohmann::json::json_pointer jsonPtr);
  bool IsECall(nlohmann::json::json_pointer jsonPtr);
  bool EnableFuzzInput(nlohmann::json::json_pointer jsonPtr);
  void dataCopy(Value *dstPtr, Value *srcPtr, Type *type, Instruction *insertPt,
                Value *arrCnt = nullptr);
  Value *createParamContent(SmallVector<Type *> types,
                            nlohmann::json::json_pointer jsonPtr,
                            std::map<uint64_t, Value *> *paramPtrs,
                            Instruction *insertPt, size_t recursion_depth = 0,
                            Value *buffer = nullptr);
  void fillAtOnce(Value *dstPtr, nlohmann::json::json_pointer jsonPtr,
                  Value *jsonPtrAsID, Instruction *insertPt,
                  Type *type = nullptr, Value *arrCnt = nullptr,
                  bool isOcall = false);
  bool hasPointerElement(Type *type);
  bool _hasPointerElement(Type *type, size_t level = 0);
  Function *createEcallFuzzWrapperFunc(std::string ecallName);
  // create content for ocall [out] pointer parameters
  void saveCreatedInput2OCallPtrParam(Function *ocallWrapper,
                                      std::string realOCallName,
                                      Instruction *insertPt);
  void createOcallFunc(std::string ocallName);
  void passStaticAnalysisResultToRuntime(
      SmallVector<Constant *> &ecallFuzzWrapperFuncs);
  void hookOCallWithWrapper(Module &M,
                            SmallVector<std::string> filteredOCallNames);
  bool runOnModule(Module &M);

private:
  FunctionCallee getIndexOfEcallToBeFuzzed, DFGetBytes, DFGetUserCheckCount,
      _strlen, _wcslen, DFEnableSetNull, DFManagedMalloc, DFManagedCalloc,
      DFEnableModifyOCallRet, DFGetPtToCntECall, DFGetPtToCntOCall;
  Module *M = nullptr;
  LLVMContext *C = nullptr;
  nlohmann::json edlJson;
  std::map<Type *, bool> typeHasPointerMap;
  TypeSerialize::DeSerializer mDeSerialzer;
  SGXSanInstVisitor mInstVisitor;
};
} // namespace llvm