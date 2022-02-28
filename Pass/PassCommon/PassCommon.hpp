#pragma once

#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Metadata.h"

#include "SGXSanManifest.h"

#include <algorithm>
#include <cstdint>

/// This struct defines the shadow mapping using the rule:
///   shadow = (mem >> Scale) ADD Offset.
struct ShadowMapping
{
    int Scale;
    uint64_t Offset;
};

ShadowMapping getShadowMapping();
uint64_t getRedzoneSizeForScale(int MappingScale);
llvm::Value *stripCast(llvm::Value *val);
llvm::StringRef SGXSanGetValueName(llvm::Value *val);
llvm::Value *getEDLInPrefixedValue(llvm::Value *val);
bool isValueNamePrefixedWith(llvm::Value *val, std::string prefix);
bool isValueNameEqualWith(llvm::Value *val, std::string name);
llvm::SmallVector<llvm::Value *> getValuesByStrInFunction(llvm::Function *F,
                                                          bool (*cmp)(llvm::Value *, std::string),
                                                          std::string str);
llvm::Value *getValueByStrInFunction(llvm::Function *F,
                                     bool (*cmp)(llvm::Value *, std::string),
                                     std::string str);
std::pair<int64_t, llvm::Value *> getLenAndValueByNameInEDL(llvm::Function *F, std::string lenPrefixedValueName);
std::pair<int64_t, llvm::Value *> getLenAndValueByParamInEDL(llvm::Function *F, llvm::Value *param);
std::tuple<int, int, llvm::Value *> convertParamLenAndValue2Tuple(llvm::Value *param,
                                                                  llvm::Function *F,
                                                                  std::pair<int64_t, llvm::Value *> lenAndValue);
llvm::Value *convertPointerLenAndValue2CountValue(llvm::Value *ptr,
                                                  llvm::Instruction *insertPoint,
                                                  std::pair<int64_t, llvm::Value *> lenAndValue);
