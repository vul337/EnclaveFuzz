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