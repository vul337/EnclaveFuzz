#include "PassCommon.hpp"
#include "llvm/Support/Debug.h"
namespace llvm
{

    Value *stripCast(Value *val)
    {
        while (CastInst *castI = dyn_cast<CastInst>(val))
        {
            val = castI->getOperand(0);
        }
        return val;
    }

    // in case that link time llvm ir doesn't have value symbol name any more
    // it seems that GlobalVariable's symbol will not filted in link time?
    StringRef SGXSanGetName(Value *val)
    {
        StringRef valName = val->getName();
        if (valName.empty())
        {
            if (Instruction *I = dyn_cast<Instruction>(val))
            {
                if (MDNode *node = I->getMetadata("SGXSanInstName"))
                {
                    valName = cast<MDString>(node->getOperand(0).get())->getString();
                }
            }
            else if (Argument *arg = dyn_cast<Argument>(val))
            {
                if (MDNode *node = arg->getParent()->getMetadata("SGXSanArgName"))
                {
                    valName = cast<MDString>(node->getOperand(arg->getArgNo()).get())->getString();
                }
            }
            // else if (GlobalVariable *GV = dyn_cast<GlobalVariable>(val))
            // {
            //     if (MDNode *node = GV->getMetadata("SGXSanGlobalName"))
            //     {
            //         valName = cast<MDString>(node->getOperand(0).get())->getString();
            //     }
            // }
        }
        return valName;
    }

    Value *getEDLInPrefixedValue(Value *val)
    {
        // directly first level
        if (SGXSanGetName(val).startswith("_in_"))
            return val;
        else
        {
            val = stripCast(val);
            if (Instruction *I = dyn_cast<Instruction>(val))
            {
                val = I->getOperand(0);
                // second level
                if (SGXSanGetName(val).startswith("_in_"))
                    return val;
            }
            return nullptr;
        }
    }

    bool isValueNamePrefixedWith(Value *val, std::string prefix)
    {
        return SGXSanGetName(val).startswith(StringRef(prefix));
    }

    bool isValueNameEqualWith(Value *val, std::string name)
    {
        return SGXSanGetName(val).str() == name;
    }

    SmallVector<Value *> getValuesByStrInFunction(Function *F, bool (*cmp)(Value *, std::string), std::string str)
    {
        SmallVector<Value *> valueVec;
        for (auto &BB : *F)
        {
            for (auto &inst : BB)
            {
                if (Value *value = dyn_cast<Value>(&inst))
                {
                    if (cmp(value, str))
                    {
                        valueVec.emplace_back(value);
                    }
                }
            }
        }
        return valueVec;
    }

    Value *getValueByStrInFunction(Function *F, bool (*cmp)(Value *, std::string), std::string str)
    {
        for (auto &BB : *F)
        {
            for (auto &inst : BB)
            {
                if (Value *value = dyn_cast<Value>(&inst))
                {
                    if (cmp(value, str))
                    {
                        return value;
                    }
                }
            }
        }
        return nullptr;
    }

    std::pair<int64_t, Value *> getLenAndValueByNameInEDL(Function *F, std::string lenPrefixedValueName)
    {
        int64_t length = -1;
        Value *lenValue = nullptr;
        SmallVector<Value *> values = getValuesByStrInFunction(F, isValueNameEqualWith, lenPrefixedValueName);
        assert(values.size() <= 1);
        if (values.size() == 0)
        {
            goto exit;
        }
        // now values.size()==1
        lenValue = values.front();
        assert(lenValue != nullptr);
        // find lenValue
        for (auto user : lenValue->users())
        {
            if (StoreInst *SI = dyn_cast<StoreInst>(user))
            {
                if (ConstantInt *cInt = dyn_cast<ConstantInt>(SI->getOperand(0)))
                {
                    length = cInt->getSExtValue();
                    assert(length > 0);
                    if (length <= 0)
                    {
                        length = -1;
                    }
                    goto exit;
                }
            }
        }
    exit:
        return std::pair<int64_t, Value *>(length, lenValue);
    }

    // fix-me: implementation is tricky
    // if (int64_t) length is not -1, then (Value *) lenValue must not be nullptr
    std::pair<int64_t, Value *> getLenAndValueByParamInEDL(Function *F, Value *param)
    {
        int64_t length = -1;
        Value *lenValue = nullptr;

        std::pair<int64_t, llvm::Value *> lenAndValue;
        param = getEDLInPrefixedValue(param);
        if (param)
        {
            // now param prefixed with _in_
            // then find _len_ prefixed value
            lenAndValue = getLenAndValueByNameInEDL(F, "_len_" + SGXSanGetName(param).substr(4).str());
            length = lenAndValue.first;
            lenValue = lenAndValue.second;
        }

        return std::pair<int64_t, Value *>(length, lenValue);
    }

    // param means passed parameter at real ecall (not ecall wrapper) instruction
    // Return:
    // ElementCnt   ElementSize LenValue
    //|-1           -1          nullptr             /* not a pointer or a function pointer */
    //|-1           >=1         nullptr             /* [user_check] pointer */
    //|-1           >=1         (Value *) _len_xxx  /* [in]/[out] pointer, but length is not a ConstantInt */
    //|>=1          >=1         (Value *) _len_xxx  /* [in]/[out] pointer, and length is a ConstantInt */
    std::tuple<int, int, Value *> convertParamLenAndValue2Tuple(Value *param, Function *F, std::pair<int64_t, Value *> lenAndValue)
    {
        int elementCnt = -1;
        int elementSize = -1;

        if (PointerType *pointerType = dyn_cast<PointerType>(param->getType()))
        {
            if (pointerType->getElementType()->isSized())
            {
                elementSize = F->getParent()->getDataLayout().getTypeAllocSize(pointerType->getElementType());
                assert(elementSize >= 1);
            }
        }
        if (elementSize != -1 && lenAndValue.first > 0 && lenAndValue.second != nullptr)
        {
            // this param is a (array-)pointer and has length, means [in]/[out]
            assert(param->getType()->isPointerTy() && (elementSize != -1));
            elementCnt = lenAndValue.first / elementSize;
            assert(elementCnt >= 1);
        }
        // else: it's a user_check (array-)ptr/string/primitive variable
        return std::tuple<int, int, Value *>(elementCnt, elementSize, lenAndValue.second);
    }

    Value *convertPointerLenAndValue2CountValue(Value *ptr, Instruction *insertPoint, std::pair<int64_t, Value *> lenAndValue)
    {
        int elementCnt = -1, elementSz = -1;
        Value *lenValue = nullptr;
        Function *F = insertPoint->getFunction();
        std::tie(elementCnt, elementSz, lenValue) = convertParamLenAndValue2Tuple(ptr, F, lenAndValue);
        IRBuilder<> IRB(insertPoint);
        if (elementCnt >= 1)
        {
            return IRB.getInt32(elementCnt);
        }
        else if (lenValue != nullptr)
        {
            return IRB.CreateIntCast(IRB.CreateExactSDiv(IRB.CreateLoad(lenValue), IRB.getInt64(elementSz)),
                                     IRB.getInt32Ty(), true);
        }
        else
        {
            return IRB.getInt32(-1);
        }
    }

    ShadowMapping getShadowMapping()
    {
        ShadowMapping Mapping;
        Mapping.Scale = 3;
        Mapping.Offset = SGXSAN_SHADOW_MAP_BASE;
        return Mapping;
    }

    uint64_t getRedzoneSizeForScale(int MappingScale)
    {
        // Redzone used for stack and globals is at least 32 bytes.
        // For scales 6 and 7, the redzone has to be 64 and 128 bytes respectively.
        return std::max(32U, 1U << MappingScale);
    }

    StringRef getDirectCalleeName(Value *value)
    {
        if (auto CI = dyn_cast<CallInst>(value))
        {
            if (auto callee = getCalledFunctionStripPointerCast(CI))
            {
                return callee->getName();
            }
        }
        return "";
    }

    StringRef getParentFuncName(Value *value)
    {
        if (auto I = dyn_cast<Instruction>(value))
        {
            return I->getFunction()->getName();
        }
        else if (Argument *arg = dyn_cast<Argument>(value))
        {
            return arg->getParent()->getName();
        }
        return "";
    }

    std::string toString(Value *val)
    {
        std::string str;
        raw_string_ostream str_ostream(str);
        val->print(str_ostream, true);
        std::stringstream ss;
        ss << "[Func] " << getParentFuncName(val).str() << " [Name] " << SGXSanGetName(val).str() << "\n"
           << str;
        return ss.str();
    }

    void dump(Value *val)
    {
        dbgs() << toString(val) << "\n\n";
    }

    uint64_t getAllocaSizeInBytes(const AllocaInst &AI)
    {
        uint64_t ArraySize = 1;
        if (AI.isArrayAllocation())
        {
            const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
            assert(CI && "non-constant array size");
            ArraySize = CI->getZExtValue();
        }
        Type *Ty = AI.getAllocatedType();
        uint64_t SizeInBytes =
            AI.getModule()->getDataLayout().getTypeAllocSize(Ty);
        return SizeInBytes * ArraySize;
    }

    Function *getCalledFunctionStripPointerCast(CallInst *CallI)
    {
        if (Function *callee = CallI->getCalledFunction())
        {
            return callee;
        }
        else if (Value *calledOp = CallI->getCalledOperand())
        {
            if (auto callee = dyn_cast<Function>(calledOp->stripPointerCasts()))
            {
                return callee;
            }
        }
        return nullptr;
    }

    SmallVector<User *> getNonCastUsers(Value *value)
    {
        SmallVector<User *> users;
        for (User *user : value->users())
        {
            if (CastInst *CastI = dyn_cast<CastInst>(user))
            {
                users.append(getNonCastUsers(CastI));
            }
            else
            {
                users.push_back(user);
            }
        }
        return users;
    }

    bool hasCmpUser(Value *val)
    {
        for (auto user : getNonCastUsers(val))
        {
            auto I = dyn_cast<Instruction>(user);
            if (I && (I->getOpcode() == Instruction::ICmp || I->getOpcode() == Instruction::FCmp))
            {
                return true;
            }
        }
        return false;
    }
}