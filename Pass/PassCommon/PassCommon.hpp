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
    Value *stripCast(Value *val);
    StringRef SGXSanGetName(Value *val);
    bool isValueNamePrefixedWith(Value *val, std::string prefix);
    bool isValueNameEqualWith(Value *val, std::string name);
    SmallVector<Value *> getValuesByStrInFunction(Function *F,
                                                  bool (*cmp)(Value *, std::string),
                                                  std::string str);
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