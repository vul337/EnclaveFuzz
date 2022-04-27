#pragma once

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Support/Debug.h"
#include "llvm/Analysis/ValueTracking.h"

#include <string>
#include <sstream>
#include <iomanip>
#include <assert.h>
#include <algorithm>

#include "AddressSanitizer.hpp"

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "sgxsan"
#endif

namespace llvm
{

    // Stack poisoning does not play well with exception handling.
    // When an exception is thrown, we essentially bypass the code
    // that unpoisones the stack. This is why the run-time library has
    // to intercept __cxa_throw (as well as longjmp, etc) and unpoison the entire
    // stack in the interceptor. This however does not work inside the
    // actual function which catches the exception. Most likely because the
    // compiler hoists the load of the shadow value somewhere too high.
    // This causes asan to report a non-existing bug on 453.povray.
    // It sounds like an LLVM bug.
    class FunctionStackPoisoner : public InstVisitor<FunctionStackPoisoner>
    {
    public:
        FunctionStackPoisoner(Function &F, AddressSanitizer &ASan);
        bool runOnFunction();
        void getRetInstVec(SmallVector<Instruction *, 8> &ReturnInstVec);
        void copyArgsPassedByValToAllocas();
        void visitReturnInst(ReturnInst &RI);
        void visitResumeInst(ResumeInst &RI);
        void visitCleanupReturnInst(CleanupReturnInst &CRI);
        void visitAllocaInst(AllocaInst &AI);
        void visitIntrinsicInst(IntrinsicInst &II);
        void visitCallBase(CallBase &CB);
        void initializeCallbacks(Module &M);
        void processDynamicAllocas();
        void processStaticAllocas();
        void poisonAlloca(Value *V, uint64_t Size,
                          IRBuilder<> &IRB, bool DoPoison);
        Value *createAllocaForLayout(
            IRBuilder<> &IRB, const ASanStackFrameLayout &L, bool Dynamic);
        void copyToShadow(ArrayRef<uint8_t> ShadowMask,
                          ArrayRef<uint8_t> ShadowBytes,
                          IRBuilder<> &IRB, Value *ShadowBase);
        void copyToShadow(ArrayRef<uint8_t> ShadowMask,
                          ArrayRef<uint8_t> ShadowBytes,
                          size_t Begin, size_t End,
                          IRBuilder<> &IRB, Value *ShadowBase);
        void copyToShadowInline(ArrayRef<uint8_t> ShadowMask,
                                ArrayRef<uint8_t> ShadowBytes,
                                size_t Begin, size_t End,
                                IRBuilder<> &IRB,
                                Value *ShadowBase);
        void createDynamicAllocasInitStorage();
        void handleDynamicAllocaCall(AllocaInst *AI);
        void unpoisonDynamicAllocas();
        void unpoisonDynamicAllocasBeforeInst(Instruction *InstBefore,
                                              Value *SavedStack);

    private:
        Function &F;
        AddressSanitizer &ASan;
        LLVMContext *C;
        Type *IntptrTy;
        Type *IntptrPtrTy;
        ShadowMapping Mapping;

        SmallVector<AllocaInst *, 16> AllocaVec;
        SmallVector<AllocaInst *, 16> StaticAllocasToMoveUp;
        SmallVector<Instruction *, 8> RetVec;
        unsigned StackAlignment;

        // Stores a place and arguments of poisoning/unpoisoning call for alloca.
        struct AllocaPoisonCall
        {
            IntrinsicInst *InsBefore;
            AllocaInst *AI;
            uint64_t Size;
            bool DoPoison;
        };
        SmallVector<AllocaPoisonCall, 8> DynamicAllocaPoisonCallVec;
        SmallVector<AllocaPoisonCall, 8> StaticAllocaPoisonCallVec;
        bool HasUntracedLifetimeIntrinsic = false;

        SmallVector<AllocaInst *, 1> DynamicAllocaVec;
        SmallVector<IntrinsicInst *, 1> StackRestoreVec;
        AllocaInst *DynamicAllocaLayout = nullptr;
        IntrinsicInst *LocalEscapeCall = nullptr;

        bool HasInlineAsm = false;
        bool HasReturnsTwiceCall = false;

        FunctionCallee AsanSetShadowFunc[0x100] = {};
        FunctionCallee AsanPoisonStackMemoryFunc, AsanUnpoisonStackMemoryFunc;
        FunctionCallee AsanAllocaPoisonFunc, AsanAllocasUnpoisonFunc;
    };
}