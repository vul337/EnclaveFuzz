#ifndef FUNCTION_STACK_POISONER_HPP
#define FUNCTION_STACK_POISONER_HPP
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Instrumentation.h"

#include <string>
#include <sstream>
#include <iomanip>
#include <assert.h>
#include <algorithm>

#include "AddressSanitizer.hpp"

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "sgxsan"
#endif

// Stack poisoning does not play well with exception handling.
// When an exception is thrown, we essentially bypass the code
// that unpoisones the stack. This is why the run-time library has
// to intercept __cxa_throw (as well as longjmp, etc) and unpoison the entire
// stack in the interceptor. This however does not work inside the
// actual function which catches the exception. Most likely because the
// compiler hoists the load of the shadow value somewhere too high.
// This causes asan to report a non-existing bug on 453.povray.
// It sounds like an LLVM bug.
class FunctionStackPoisoner : public llvm::InstVisitor<FunctionStackPoisoner>
{
public:
    FunctionStackPoisoner(llvm::Function &F, AddressSanitizer &ASan);
    bool runOnFunction();
    void copyArgsPassedByValToAllocas();
    void visitReturnInst(llvm::ReturnInst &RI);
    void visitResumeInst(llvm::ResumeInst &RI);
    void visitCleanupReturnInst(llvm::CleanupReturnInst &CRI);
    void visitAllocaInst(llvm::AllocaInst &AI);
    void initializeCallbacks(llvm::Module &M);
    void processStaticAllocas();
    llvm::Value *createAllocaForLayout(
        llvm::IRBuilder<> &IRB, const llvm::ASanStackFrameLayout &L, bool Dynamic);
    void copyToShadow(llvm::ArrayRef<uint8_t> ShadowMask,
                      llvm::ArrayRef<uint8_t> ShadowBytes,
                      llvm::IRBuilder<> &IRB, llvm::Value *ShadowBase);
    void copyToShadow(llvm::ArrayRef<uint8_t> ShadowMask,
                      llvm::ArrayRef<uint8_t> ShadowBytes,
                      size_t Begin, size_t End,
                      llvm::IRBuilder<> &IRB, llvm::Value *ShadowBase);
    void copyToShadowInline(llvm::ArrayRef<uint8_t> ShadowMask,
                            llvm::ArrayRef<uint8_t> ShadowBytes,
                            size_t Begin, size_t End,
                            llvm::IRBuilder<> &IRB,
                            llvm::Value *ShadowBase);

private:
    llvm::Function &F;
    AddressSanitizer &ASan;
    llvm::LLVMContext *C;
    llvm::Type *IntptrTy;
    llvm::Type *IntptrPtrTy;
    ShadowMapping Mapping;

    llvm::SmallVector<llvm::AllocaInst *, 16> AllocaVec;
    llvm::SmallVector<llvm::AllocaInst *, 16> StaticAllocasToMoveUp;
    llvm::SmallVector<llvm::Instruction *, 8> RetVec;
    unsigned StackAlignment;

    llvm::FunctionCallee AsanSetShadowFunc[0x100] = {};
};
#endif //FUNCTION_STACK_POISONER_HPP