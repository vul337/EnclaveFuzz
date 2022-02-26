#pragma once

#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Instrumentation.h"

#include "ASanCommon.hpp"

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "sgxsan"
#endif

class ModuleAddressSanitizer
{
public:
    ModuleAddressSanitizer(llvm::Module &M,
                           bool UseOdrIndicator = false);
    void initializeCallbacks(llvm::Module &M);
    bool instrumentModule(llvm::Module &module);
    static uint64_t GetCtorAndDtorPriority();
    bool InstrumentGlobals(llvm::IRBuilder<> &IRB, llvm::Module &M,
                           bool *CtorComdat);
    uint64_t getRedzoneSizeForGlobal(uint64_t SizeInBytes) const;
    uint64_t getMinRedzoneSizeForGlobal() const;
    void InstrumentGlobalsWithMetadataArray(
        llvm::IRBuilder<> &IRB, llvm::Module &M, llvm::ArrayRef<llvm::GlobalVariable *> ExtendedGlobals,
        llvm::ArrayRef<llvm::Constant *> MetadataInitializers);
    llvm::Instruction *CreateAsanModuleDtor(llvm::Module &M);
    bool shouldInstrumentGlobal(llvm::GlobalVariable *G) const;

private:
    llvm::Function *AsanCtorFunction = nullptr;
    llvm::Function *AsanDtorFunction = nullptr;
    llvm::LLVMContext *C;
    llvm::Type *IntptrTy;
    ShadowMapping Mapping;
    llvm::FunctionCallee AsanRegisterGlobals;
    llvm::FunctionCallee AsanUnregisterGlobals;

    bool UsePrivateAlias;
    bool UseOdrIndicator;
};