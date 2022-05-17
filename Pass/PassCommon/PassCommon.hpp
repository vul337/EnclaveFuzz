#pragma once

#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Metadata.h"

#include "SGXSanManifest.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <sstream>

namespace llvm
{
    /// This struct defines the shadow mapping using the rule:
    ///   shadow = (mem >> Scale) ADD Offset.
    struct ShadowMapping
    {
        int Scale;
        uint64_t Offset;
    };

    ShadowMapping getShadowMapping();
    uint64_t getRedzoneSizeForScale(int MappingScale);
    Value *stripCast(Value *val);
    StringRef SGXSanGetName(Value *val);
    Value *getEDLInPrefixedValue(Value *val);
    bool isValueNamePrefixedWith(Value *val, std::string prefix);
    bool isValueNameEqualWith(Value *val, std::string name);
    SmallVector<Value *> getValuesByStrInFunction(Function *F,
                                                  bool (*cmp)(Value *, std::string),
                                                  std::string str);
    Value *getValueByStrInFunction(Function *F,
                                   bool (*cmp)(Value *, std::string),
                                   std::string str);
    std::pair<int64_t, Value *> getLenAndValueByNameInEDL(Function *F, std::string lenPrefixedValueName);
    std::pair<int64_t, Value *> getLenAndValueByParamInEDL(Function *F, Value *param);
    std::tuple<int, int, Value *> convertParamLenAndValue2Tuple(Value *param,
                                                                Function *F,
                                                                std::pair<int64_t, Value *> lenAndValue);
    Value *convertPointerLenAndValue2CountValue(Value *ptr,
                                                Instruction *insertPoint,
                                                std::pair<int64_t, Value *> lenAndValue);
    // if value isn't a direct CallInst, it return empty ""
    StringRef getDirectCalleeName(Value *value);
    // it value isn't instrcution, return empty ""
    StringRef getParentFuncName(Value *value);
    std::string toString(Value *val);
    void dump(Value *val);
    uint64_t getAllocaSizeInBytes(const AllocaInst &AI);
    Function *getCalledFunctionStripPointerCast(CallInst *CallI);
    SmallVector<User *> getNonCastUsers(Value *value);
    bool hasCmpUser(Value *val);
}