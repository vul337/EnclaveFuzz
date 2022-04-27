#pragma once

#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Instrumentation.h"

#include "PassCommon.hpp"

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "sgxsan"
#endif

namespace llvm
{
    class ModuleAddressSanitizer
    {
    public:
        ModuleAddressSanitizer(Module &M,
                               bool UseOdrIndicator = false);
        void initializeCallbacks(Module &M);
        bool instrumentModule(Module &module);
        static uint64_t GetCtorAndDtorPriority();
        bool InstrumentGlobals(IRBuilder<> &IRB, Module &M,
                               bool *CtorComdat);
        uint64_t getRedzoneSizeForGlobal(uint64_t SizeInBytes) const;
        uint64_t getMinRedzoneSizeForGlobal() const;
        void InstrumentGlobalsWithMetadataArray(
            IRBuilder<> &IRB, Module &M, ArrayRef<GlobalVariable *> ExtendedGlobals,
            ArrayRef<Constant *> MetadataInitializers);
        Instruction *CreateAsanModuleDtor(Module &M);
        bool shouldInstrumentGlobal(GlobalVariable *G) const;

    private:
        Function *AsanCtorFunction = nullptr;
        Function *AsanDtorFunction = nullptr;
        LLVMContext *C;
        Type *IntptrTy;
        ShadowMapping Mapping;
        FunctionCallee AsanRegisterGlobals;
        FunctionCallee AsanUnregisterGlobals;

        bool UsePrivateAlias;
        bool UseOdrIndicator;
    };
}