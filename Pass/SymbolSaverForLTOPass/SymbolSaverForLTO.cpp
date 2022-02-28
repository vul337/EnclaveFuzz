#include "SymbolSaverForLTO.hpp"
#include "PassCommon.hpp"

using namespace llvm;

SymbolSaverForLTO::SymbolSaverForLTO(Module &M)
{
    C = &M.getContext();
}

void SymbolSaverForLTO::saveGlobalName2Metadata(Module &M)
{
    for (auto &g : M.globals())
    {
        StringRef globalName = g.getName();
        if (not globalName.empty())
        {
            auto node = MDNode::get(*C, MDString::get(*C, globalName));
            g.setMetadata("SGXSanGlobalName", node);
        }
    }
}

bool SymbolSaverForLTO::runOnModule(Module &M)
{
    saveGlobalName2Metadata(M);

    for (Function &F : M)
    {
        if (!F.isDeclaration())
        {
            saveArgName2Metadata(F);
            saveInstName2Metadata(F);
        }
    }

    return true;
}

void SymbolSaverForLTO::saveArgName2Metadata(Function &F)
{
    SmallVector<Metadata *> argNameMDs;
    for (Argument &arg : F.args())
    {
        argNameMDs.push_back(MDString::get(*C, arg.getName()));
    }

    auto node = MDNode::get(*C, ArrayRef<Metadata *>(argNameMDs));
    F.setMetadata("SGXSanArgName", node);
}

void SymbolSaverForLTO::saveInstName2Metadata(Function &F)
{
    for (BasicBlock &BB : F)
    {
        for (Instruction &I : BB)
        {
            StringRef instName = I.getName();
            if (not instName.empty())
            {
                auto node = MDNode::get(*C, MDString::get(*C, instName));
                I.setMetadata("SGXSanInstName", node);
            }
        }
    }
}