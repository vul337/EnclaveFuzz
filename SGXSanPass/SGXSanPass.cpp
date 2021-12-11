#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "AddressSanitizer.hpp"
#include "SGXSanManifest.h"

using namespace llvm;

namespace
{
    struct SGXSanPass : public ModulePass
    {
        static char ID;
        SGXSanPass() : ModulePass(ID) {}

        bool runOnModule(Module &M) override
        {
            bool Changed = false;
            AddressSanitizer ASan(M);
            for (Function &F : M)
            {

                // errs() << "Hello: " << F.getName() << '\n';
                // (https://stackoverflow.com/questions/30990032/change-name-of-llvm-function)
                StringRef func_name = F.getName();
                if (func_name == "memcpy_s")
                {
                    F.setName("sgxsan_memcpy_s");
                }
                else if (func_name == "memset_s")
                {
                    F.setName("sgxsan_memset_s");
                }
                else if (func_name == "memmove_s")
                {
                    F.setName("sgxsan_memmove_s");
                }
#if (USE_SGXSAN_MALLOC)
                else if (func_name == "malloc")
                {
                    F.setName("sgxsan_malloc");
                }
                else if (func_name == "free")
                {
                    F.setName("sgxsan_free");
                }
                else if (func_name == "realloc")
                {
                    F.setName("sgxsan_realloc");
                }
                else if (func_name == "calloc")
                {
                    F.setName("sgxsan_calloc");
                }
#endif
                // cauze WhitelistQuery will call sgxsan_printf, so we shouldn't instrument sgxsan_printf with WhitelistQuery
                if ((not F.isDeclaration()) and (func_name != "ocall_init_shadow_memory") and
                    (func_name != "sgxsan_printf") and (func_name != "sgxsan_ocall_print_string"))
                {
                    Changed |= ASan.instrumentFunction(F);
                }
            }
            return Changed;
        }

        // bool runOnFunction(Function &F) override
        // {
        //     AddressSanitizer ASan(*F.getParent());

        //     return ASan.instrumentFunction(F);
        // }
    }; // end of struct SGXSanPass
} // end of anonymous namespace

char SGXSanPass::ID = 1;
static RegisterPass<SGXSanPass> X("SGXSanPass", "SGXSanPass",
                                  false /* Only looks at CFG */,
                                  false /* Analysis Pass */);

static RegisterStandardPasses Y(
    PassManagerBuilder::EP_EnabledOnOptLevel0, // EP_EarlyAsPossible can only be used in FunctionPass(https://lists.llvm.org/pipermail/llvm-dev/2018-June/123987.html)
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SGXSanPass()); });