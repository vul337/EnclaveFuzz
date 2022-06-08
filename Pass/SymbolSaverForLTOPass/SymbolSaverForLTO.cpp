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
            node = MDNode::get(*C, MDString::get(*C, "Annotation"));
            g.setMetadata("NAME:" + globalName.str(), node);
        }
    }
}

bool SymbolSaverForLTO::runOnModule(Module &M)
{
    // global name will not be erased at link time, so needn't to do this
    // saveGlobalName2Metadata(M);

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
    std::string argNames = "NAME:";
    for (Argument &arg : F.args())
    {
        argNameMDs.push_back(MDString::get(*C, arg.getName()));
        argNames = argNames + arg.getName().str() + ";";
    }

    auto node = MDNode::get(*C, ArrayRef<Metadata *>(argNameMDs));
    F.setMetadata("SGXSanArgName", node);
    if (argNames != "")
    {
        node = MDNode::get(*C, MDString::get(*C, "Annotation"));
        F.setMetadata(argNames, node);
    }
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
                node = MDNode::get(*C, MDString::get(*C, "Annotation"));
                I.setMetadata("NAME:" + instName.str(), node);
            }
        }
    }
}