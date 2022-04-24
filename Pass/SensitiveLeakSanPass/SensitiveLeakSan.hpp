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

class SensitiveLeakSan
{

public:
    SensitiveLeakSan(llvm::Module &M, llvm::CFLSteensAAResult &AAResult);
    void includeThreadFuncArgShadow();
    void includeElrange();
    void includeSGXSanCheck();
    void initSVF();
    bool runOnModule();
    void collectAndPoisonSensitiveObj(llvm::Module &M);
    void doVFA(llvm::Value *work);
    void pushSensitiveObj(llvm::Value *annotatedVar);
    void instrumentSensitiveInstObjPoison(SVF::ObjPN *objPN);
    llvm::Value *memToShadow(llvm::Value *Shadow, llvm::IRBuilder<> &IRB);
    llvm::Value *memToShadowPtr(llvm::Value *memPtr, llvm::IRBuilder<> &IRB);

    int getCallInstOperandPosition(llvm::CallInst *CI, llvm::Value *oprend, bool rawOperand = false);
    void getDirectAndIndirectCalledFunction(llvm::CallInst *CI, llvm::SmallVector<llvm::Function *> &calleeVec);
    llvm::Instruction *findInstByName(llvm::Function *F, std::string InstName);
    void getPtrValPNs(SVF::ObjPN *obj, std::unordered_set<SVF::ValPN *> &oneLevelPtrs);
    void add2SensitiveObjAndPoison(SVF::ObjPN *obj);
    static llvm::Value *RoundUpUDiv(llvm::IRBuilder<> &IRB, llvm::Value *size, uint64_t dividend);
    uint64_t RoundUpUDiv(uint64_t dividend, uint64_t divisor);
    void addPtObj2WorkList(llvm::Value *ptr);
    static llvm::StringRef getBelongedFunctionName(SVF::PAGNode *node);
    static llvm::StringRef getBelongedFunctionName(llvm::Value *val);
    void setNoSanitizeMetadata(llvm::Instruction *I);
    void propagateShadowInMemTransfer(llvm::CallInst *CI, llvm::Instruction *insertPoint, llvm::Value *destPtr,
                                      llvm::Value *srcPtr, llvm::Value *size);
    uint64_t getPointerElementSize(llvm::Value *ptr);
    llvm::Value *getHeapObjSize(llvm::CallInst *obj, llvm::IRBuilder<> &IRB);
    void getNonPointerObjPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ObjPN *> &objs);
    void getNonPointerObjPNs(llvm::Value *value, std::unordered_set<SVF::ObjPN *> &objs);
    llvm::Value *instrumentPoisonCheck(llvm::Value *src);
    llvm::Value *isLIPoisoned(llvm::LoadInst *src);
    llvm::Value *isArgPoisoned(llvm::Argument *src);
    llvm::Value *isCIRetPoisoned(llvm::CallInst *src);
    llvm::Value *isPtrPoisoned(llvm::Instruction *insertPoint, llvm::Value *ptr);
    static int getPointerLevel(llvm::Value *ptr);
    void PoisonCIOperand(llvm::Value *src, llvm::Value *isPoisoned, llvm::CallInst *CI, int operandPosition);
    void PoisonSI(llvm::Value *src, llvm::Value *isPoisoned, llvm::StoreInst *SI);
    void PoisonRetShadow(llvm::Value *src, llvm::Value *isPoisoned, llvm::ReturnInst *calleeRI);
    void PoisonMemsetDst(llvm::Value *src, llvm::Value *isSrcPoisoned, llvm::CallInst *MSI, llvm::Value *dstPtr, llvm::Value *setSize);
    static llvm::Value *stripCast(llvm::Value *v);
    void propagateShadow(llvm::Value *src);
    uint64_t getTypeAllocaSize(llvm::Type *type);
    static bool isAnnotationIntrinsic(llvm::CallInst *CI);
    static std::string extractAnnotation(llvm::Value *annotationStrVal);
    static bool isSecureVersionMemTransferCI(llvm::CallInst *CI);
    static bool StringRefContainWord(llvm::StringRef str, std::string word);
    static bool isEncryptionFunction(llvm::Function *F);
    // void cleanStackObjectSensitiveShadow(llvm::Value *stackObject);
    void PoisonObject(llvm::Value *objPtr, llvm::Value *objSize, llvm::IRBuilder<> &IRB, uint8_t poisonValue);
    static void getNonCastUsers(llvm::Value *value, std::vector<llvm::User *> &users);
    void poisonSensitiveGlobalVariableAtRuntime();
    void initializeCallbacks();
    // void cleanStackObjectSensitiveShadow(SVF::ObjPN *objPN);
    llvm::Value *getStackOrHeapInstObjSize(llvm::Instruction *objI, llvm::IRBuilder<> &IRB);
    void dumpPts(SVF::PAGNode *PN);
    void dumpRevPts(SVF::PAGNode *PN);
    void pushAndPopArgShadowFrameAroundCallInst(llvm::CallInst *CI);
    static std::string toString(SVF::PAGNode *PN);
    static std::string toString(llvm::Value *val);
    static void dump(SVF::PAGNode *PN);
    static void dump(llvm::Value *val);
    void dump(SVF::NodeID nodeID);
    static llvm::StringRef SGXSanGetPNName(SVF::PAGNode *PN);
    bool isFunctionObjPN(SVF::PAGNode *PN);
    void printStrAtRT(llvm::IRBuilder<> &IRB, std::string str);
    void printSrcAtRT(llvm::IRBuilder<> &IRB, llvm::Value *src);
    void collectHeapAllocators();
    void collectHeapAllocatorGlobalPtrs();
    bool isHeapAllocatorWrapper(llvm::Function &F);

private:
    std::unordered_set<SVF::ObjPN *> SensitiveObjs, WorkList, ProcessedList;
    std::unordered_set<llvm::Value *> poisonedInst, cleanedStackObjs;
    std::unordered_set<llvm::CallInst *> processedMemTransferInst;
    std::unordered_map<llvm::CallInst *, std::unordered_set<int>> poisonedCI;
    std::unordered_map<llvm::Value *, llvm::Value *> poisonCheckedValues;
    llvm::GlobalVariable *SGXSanEnclaveBaseAddr = nullptr, *SGXSanEnclaveSizeAddr = nullptr, *ThreadFuncArgShadow = nullptr;
    llvm::FunctionCallee poison_thread_func_arg_shadow_stack,
        unpoison_thread_func_arg_shadow_stack, onetime_query_thread_func_arg_shadow_stack,
        query_thread_func_arg_shadow_stack, clear_thread_func_arg_shadow_stack,
        push_thread_func_arg_shadow_stack, pop_thread_func_arg_shadow_stack,
        sgxsan_region_is_poisoned, is_addr_in_elrange, is_addr_in_elrange_ex,
        sgxsan_region_is_in_elrange_and_poisoned,
        PoisonSensitiveGlobal, Abort, Printf, print_ptr, print_arg, __sgxsan_shallow_poison_valid_shadow, func_malloc_usable_size;

    llvm::Module *M = nullptr;
    llvm::LLVMContext *C = nullptr;
    llvm::Type *IntptrTy = nullptr;

    SVF::SVFModule *svfModule = nullptr;
    SVF::PAG *pag = nullptr;
    SVF::Andersen *ander = nullptr;
    SVF::PTACallGraph *callgraph = nullptr;

    SGXSanInstVisitor *instVisitor = nullptr;
    llvm::SmallVector<llvm::Constant *> globalsToBePolluted;
    llvm::Function *PoisonSensitiveGlobalModuleCtor = nullptr;
    llvm::Constant *StrSpeicifier = nullptr;
    std::set<llvm::Function *> heapAllocators;
    std::set<llvm::GlobalVariable *> heapAllocatorGlobalPtrs;
    llvm::CFLSteensAAResult *AAResult = nullptr;
    std::unordered_set<std::string> heapAllocatorBaseNames{"malloc", "calloc", "realloc"},
        heapAllocatorWrapperNames, heapAllocatorNames,
        plaintextParamKeywords = {"2encrypt", "unencrypt", "src", "source", "2seal", "unseal", "plain", "in", "key"};
};
