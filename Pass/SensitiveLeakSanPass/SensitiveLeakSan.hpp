#pragma once

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/CFLSteensAliasAnalysis.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/CommandLine.h"

#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/PAGBuilder.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "WPA/FlowSensitiveTBHC.h"
#include "SABER/LeakChecker.h"
#include "DDA/ContextDDA.h"
#include "DDA/DDAClient.h"
#include "MemoryModel/ConditionalPT.h"
#include "Util/DPItem.h"

#include "SGXSanInstVisitor.hpp"
#include "PassCommon.hpp"

#include <unordered_set>
#include <unordered_map>
#include <regex>

namespace llvm
{
    class SensitiveLeakSan
    {
    public:
        SensitiveLeakSan(Module &M, CFLSteensAAResult &AAResult);
        void includeThreadFuncArgShadow();
        void includeElrange();
        void includeSGXSanCheck();
        void initSVF();
        bool runOnModule();
        void collectAndPoisonSensitiveObj();
        void doVFA(Value *work);
        void pushSensitiveObj(Value *annotatedVar);
        void instrumentSensitiveInstObjPoison(SVF::ObjPN *objPN);
        Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
        Value *memToShadowPtr(Value *memPtr, IRBuilder<> &IRB);

        int getCallInstOperandPosition(CallInst *CI, Value *oprend, bool rawOperand = false);
        void getDirectAndIndirectCalledFunction(CallInst *CI, SmallVector<Function *> &calleeVec);
        Instruction *findInstByName(Function *F, std::string InstName);
        void getPtrValPNs(SVF::ObjPN *obj, std::unordered_set<SVF::ValPN *> &oneLevelPtrs);
        void add2SensitiveObjAndPoison(SVF::ObjPN *obj);
        static Value *RoundUpUDiv(IRBuilder<> &IRB, Value *size, uint64_t dividend);
        uint64_t RoundUpUDiv(uint64_t dividend, uint64_t divisor);
        void addPtObj2WorkList(Value *ptr);
        static StringRef getParentFuncName(SVF::PAGNode *node);
        void setNoSanitizeMetadata(Instruction *I);
        void propagateShadowInMemTransfer(CallInst *CI, Instruction *insertPoint, Value *destPtr,
                                          Value *srcPtr, Value *size);
        uint64_t getPointerElementSize(Value *ptr);
        Value *getHeapObjSize(CallInst *obj, IRBuilder<> &IRB);
        void getNonPointerObjPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ObjPN *> &objs);
        void getNonPointerObjPNs(Value *value, std::unordered_set<SVF::ObjPN *> &objs);
        Value *instrumentPoisonCheck(Value *src);
        Value *isLIPoisoned(LoadInst *src);
        Value *isArgPoisoned(Argument *src);
        Value *isCIRetPoisoned(CallInst *src);
        Value *isPtrPoisoned(Instruction *insertPoint, Value *ptr);
        static int getPointerLevel(Value *ptr);
        void PoisonCIOperand(Value *src, Value *isPoisoned, CallInst *CI, int operandPosition);
        void PoisonSI(Value *src, Value *isPoisoned, StoreInst *SI);
        void PoisonRetShadow(Value *src, Value *isPoisoned, ReturnInst *calleeRI);
        void PoisonMemsetDst(Value *src, Value *isSrcPoisoned, CallInst *MSI, Value *dstPtr, Value *setSize);
        static Value *stripCast(Value *v);
        void propagateShadow(Value *src);
        static bool isAnnotationIntrinsic(CallInst *CI);
        static std::string extractAnnotation(Value *annotationStrVal);
        static bool isSecureVersionMemTransferCI(CallInst *CI);
        static bool StringRefContainWord(StringRef str, std::string word);
        static bool isEncryptionFunction(Function *F);
        static void getNonCastUsers(Value *value, std::vector<User *> &users);
        void poisonSensitiveGlobalVariableAtRuntime();
        void initializeCallbacks();
        void cleanStackObjectSensitiveShadow(Value *stackObject);
        void cleanStackObjectSensitiveShadow(SVF::ObjPN *objPN);
        Value *getStackOrHeapInstObjSize(Instruction *objI, IRBuilder<> &IRB);
        void dumpPts(SVF::PAGNode *PN);
        void dumpRevPts(SVF::PAGNode *PN);
        void pushAndPopArgShadowFrameAroundCallInst(CallInst *CI);
        static std::string toString(SVF::PAGNode *PN);
        static void dump(SVF::PAGNode *PN);
        void dump(SVF::NodeID nodeID);
        static StringRef SGXSanGetName(SVF::PAGNode *PN);
        bool isFunctionObjPN(SVF::PAGNode *PN);
        void printStrAtRT(IRBuilder<> &IRB, std::string str);
        void printSrcAtRT(IRBuilder<> &IRB, Value *src);
        void collectHeapAllocators();
        void collectHeapAllocatorGlobalPtrs();
        bool isHeapAllocatorWrapper(Function &F);
        bool hasObjectNode(Value *val);

    private:
        std::unordered_set<SVF::ObjPN *> SensitiveObjs, WorkList, ProcessedList;
        std::unordered_set<Value *> poisonedInst;
        std::unordered_set<AllocaInst *> cleanedStackObjs;
        std::unordered_set<CallInst *> processedMemTransferInst;
        std::unordered_map<CallInst *, std::unordered_set<int>> poisonedCI;
        std::unordered_map<Value *, Value *> poisonCheckedValues;
        GlobalVariable *SGXSanEnclaveBaseAddr = nullptr, *SGXSanEnclaveSizeAddr = nullptr, *ThreadFuncArgShadow = nullptr;
        FunctionCallee poison_thread_func_arg_shadow_stack,
            unpoison_thread_func_arg_shadow_stack, onetime_query_thread_func_arg_shadow_stack,
            query_thread_func_arg_shadow_stack, clear_thread_func_arg_shadow_stack,
            push_thread_func_arg_shadow_stack, pop_thread_func_arg_shadow_stack,
            sgxsan_region_is_poisoned, is_addr_in_elrange, is_addr_in_elrange_ex,
            sgxsan_region_is_in_elrange_and_poisoned,
            PoisonSensitiveGlobal, Abort, Printf, print_ptr, print_arg, __sgxsan_shallow_poison_object, func_malloc_usable_size;

        Module *M = nullptr;
        LLVMContext *C = nullptr;
        Type *IntptrTy = nullptr;

        SVF::SVFModule *svfModule = nullptr;
        SVF::PAG *pag = nullptr;
        SVF::Andersen *ander = nullptr;
        SVF::PTACallGraph *callgraph = nullptr;
        SVF::SymbolTableInfo *symInfo = nullptr;

        SmallVector<Constant *> globalsToBePolluted;
        Function *PoisonSensitiveGlobalModuleCtor = nullptr;
        Constant *StrSpeicifier = nullptr;
        std::set<Function *> heapAllocators;
        std::set<GlobalVariable *> heapAllocatorGlobalPtrs;
        CFLSteensAAResult *AAResult = nullptr;
        std::unordered_set<std::string> heapAllocatorBaseNames{"malloc", "calloc", "realloc"},
            heapAllocatorWrapperNames, heapAllocatorNames,
            plaintextParamKeywords = {"2encrypt", "unencrypt", "src", "source", "2seal", "unseal", "plain", "in", "key"};
    };
}
