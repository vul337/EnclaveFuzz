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

  /// @brief I don't use jsonPtr.to_string() as jsonPtrAsID, instead, I use
  /// parentID+currentID, since later has InstanceID info
  /// @param types
  /// @param jsonPtr
  /// @param parentID
  /// @param currentID
  /// @param paramPtrs
  /// @param insertPt
  /// @param recursion_depth
  /// @return
  Value *createParamContent(SmallVector<Type *> types,
                            nlohmann::json::json_pointer jsonPtr,
                            Value *parentID, Value *currentID,
                            std::map<uint64_t, Value *> *paramPtrs,
                            Instruction *insertPt, size_t recursion_depth = 0);
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
  FunctionCallee getIndexOfEcallToBeFuzzed, getFuzzDataPtr, getUserCheckCount,
      _strlen, _wcslen, whetherSetNullPointer, DFJoinID, DFGetInstanceID,
      DFManagedMalloc;
  Constant *GStr0 = nullptr, *GStrField = nullptr, *GNullInt8Ptr = nullptr;
  Module *M = nullptr;
  LLVMContext *C = nullptr;
  nlohmann::json edlJson;
  std::map<Type *, bool> typeHasPointerMap;
};
} // namespace llvm