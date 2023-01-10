#pragma once
#include "nlohmann/json.hpp"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Debug.h"
#include <regex>

std::string GetTypeName(const llvm::Type *ty);

namespace TypeSerialize {
class Serializer {
public:
  void SerializeStructType(llvm::StructType *structTy,
                           nlohmann::ordered_json &json);

private:
  static void RecGetTypeJson(nlohmann::ordered_json &json,
                             const llvm::Type *ty);
};

class DeSerializer {
public:
  void init(llvm::LLVMContext *C, const nlohmann::ordered_json &TypeJson);
  void update(const nlohmann::ordered_json &TypeJson) {
    if (not TypeJson.is_null())
      mTypeJson.update(TypeJson);
  }
  void dump() { llvm::dbgs() << mTypeJson.dump(4) << "\n"; }
  void ResolveOpaqueStruct(llvm::StructType *OpaqueStructTy);

private:
  llvm::Type *GetType(nlohmann::ordered_json &json);
  llvm::LLVMContext *C;
  std::unordered_map<std::string, llvm::Type *> mStr2Type;
  nlohmann::ordered_json mTypeJson;
};
} // namespace TypeSerialize