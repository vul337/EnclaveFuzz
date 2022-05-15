#pragma once

#include "llvm/IR/Function.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/ADT/Statistic.h"
#include <assert.h>
#include "SGXSanManifest.h"
#include "PassCommon.hpp"
#include <unordered_set>

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "sgxsan"
#endif

namespace llvm
{
    // Accesses sizes are powers of two: 1, 2, 4, 8, 16.
    static const size_t kNumberOfAccessSizes = 5;

    class AddressSanitizer
    {
    public:
        AddressSanitizer(Module &M, bool UseAfterScope = false);
        bool instrumentFunction(Function &F);
        void initializeCallbacks(Module &M);
        void getInterestingMemoryOperands(Instruction *I, SmallVectorImpl<InterestingMemoryOperand> &Interesting, SmallVector<StoreInst *, 16> &GlobalVariableStoreInsts);
        void instrumentMop(InterestingMemoryOperand &O, bool UseCalls);
        void instrumentGlobalPropageteWhitelist(StoreInst *SI);
        bool instrumentRealEcall(CallInst *CI, SmallVector<Instruction *> &ReturnInstVec);
        bool instrumentOcallWrapper(Function &OcallWrapper, SmallVector<Instruction *> &ReturnInstVec);
        bool instrumentParameterCheck(Value *operand, IRBuilder<> &IRB, const DataLayout &DL,
                                      int depth, Value *eleCnt = nullptr, Value *operandAddr = nullptr,
                                      bool checkCurrentLevelPtr = true);
        void instrumentAddress(Instruction *OrigIns, Instruction *InsertBefore, Value *Addr,
                               uint32_t TypeSize, bool IsWrite, Value *SizeArgument, bool UseCalls);
        void instrumentUnusualSizeOrAlignment(
            Instruction *I, Instruction *InsertBefore, Value *Addr, uint32_t TypeSize,
            bool IsWrite, Value *SizeArgument, bool UseCalls);
        void declareExternElrangeSymbol(Module &M);
        Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
        Value *createSlowPathCmp(IRBuilder<> &IRB, Value *AddrLong,
                                 Value *ShadowValue,
                                 uint32_t TypeSize);
        Instruction *generateCrashCode(Instruction *InsertBefore,
                                       Value *Addr, bool IsWrite,
                                       size_t AccessSizeIndex,
                                       Value *SizeArgument);
        void instrumentMemIntrinsic(MemIntrinsic *MI);
        void instrumentSecMemIntrinsic(CallInst *CI);
#if (USE_SGXSAN_MALLOC)
        void instrumentHeapCall(CallInst *CI);
#endif
        bool isInterestingAlloca(const AllocaInst &AI);
        uint64_t getAllocaSizeInBytes(const AllocaInst &AI) const;
        bool ignoreAccess(Value *Ptr);
        static Type *unpackArrayType(Type *type);

    private:
        friend class FunctionStackPoisoner;
        LLVMContext *C;
        int LongSize;
        bool UseAfterScope;
        Type *IntptrTy;
        ShadowMapping Mapping;
        FunctionCallee AsanHandleNoReturnFunc;

        // These arrays is indexed by AccessIsWrite, Experiment and log2(AccessSize).
        FunctionCallee AsanErrorCallback[2][kNumberOfAccessSizes];
        FunctionCallee AsanMemoryAccessCallback[2][kNumberOfAccessSizes];

        // These arrays is indexed by AccessIsWrite and Experiment.
        FunctionCallee AsanErrorCallbackSized[2];
        FunctionCallee AsanMemoryAccessCallbackSized[2];

        FunctionCallee AsanMemmove, AsanMemcpy, AsanMemset;
        Value *LocalDynamicShadow = nullptr;

        DenseMap<const AllocaInst *, bool> ProcessedAllocas;

        GlobalVariable *ExternSGXSanEnclaveBaseAddr, *ExternSGXSanEnclaveSizeAddr;

        FunctionCallee WhitelistOfAddrOutEnclave_active, WhitelistOfAddrOutEnclave_deactive,
            WhitelistOfAddrOutEnclave_query, WhitelistOfAddrOutEnclave_global_propagate,
            sgxsan_edge_check, SGXSanMemcpyS, SGXSanMemsetS, SGXSanMemmoveS,
            EnclaveTLSConstructorAtTBridgeBegin, EnclaveTLSDestructorAtTBridgeEnd;
#if (USE_SGXSAN_MALLOC)
        FunctionCallee SGXSanMalloc, SGXSanFree, SGXSanCalloc, SGXSanRealloc;
#endif
        std::unordered_set<Function *> TLSMgrInstrumentedEcall;
    };
}
