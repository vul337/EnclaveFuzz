#pragma once

#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"

llvm::Value *stripCast(llvm::Value *val);
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