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
    enum SensitiveLevel
    {
        NOT_SENSITIVE = 0,
        MAY_BE_SENSITIVE,
        IS_SENSITIVE
    };

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
        void poisonSensitiveStackOrHeapObj(SVF::ObjPN *objPN, std::pair<uint8_t *, size_t> *shadowBytesPair);
        Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
        Value *memPtrToShadowPtr(Value *memPtr, IRBuilder<> &IRB);

        int getCallInstOperandPosition(CallInst *CI, Value *oprend, bool rawOperand = false);
        void getDirectAndIndirectCalledFunction(CallInst *CI, SmallVector<Function *> &calleeVec);
        Instruction *findInstByName(Function *F, std::string InstName);
        void getPtrValPNs(SVF::ObjPN *obj, std::unordered_set<SVF::ValPN *> &oneLevelPtrs);
        void addAndPoisonSensitiveObj(SVF::ObjPN *obj, std::pair<uint8_t *, size_t> *shadowBytesPair = nullptr);
        void addAndPoisonSensitiveObj(SVF::ObjPN *objPN, SensitiveLevel sensitiveLevel);
        void addAndPoisonSensitiveObj(Value *obj);
        Value *RoundUpUDiv(IRBuilder<> &IRB, Value *size, uint64_t dividend);
        uint64_t RoundUpUDiv(uint64_t dividend, uint64_t divisor);
        void addPtObj2WorkList(Value *ptr);
        static StringRef getParentFuncName(SVF::PAGNode *node);
        void setNoSanitizeMetadata(Instruction *I);
        void propagateShadowInMemTransfer(CallInst *CI, Instruction *insertPoint, Value *destPtr,
                                          Value *srcPtr, Value *dstSize, Value *copyCnt);
        uint64_t getPointerElementSize(Value *ptr);
        Value *getHeapObjSize(CallInst *obj, IRBuilder<> &IRB);
        void getNonPointerObjPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ObjPN *> &objPNs);
        void getNonPointerObjPNs(Value *value, std::unordered_set<SVF::ObjPN *> &objPNs);
        Value *instrumentPoisonCheck(Value *src);
        Value *isLIPoisoned(LoadInst *src);
        Value *isArgPoisoned(Argument *src);
        Value *isCIRetPoisoned(CallInst *src);
        Value *isPtrPoisoned(Instruction *insertPoint, Value *ptr, Value *size = nullptr);
        static int getPointerLevel(const Value *ptr);
        void PoisonCIOperand(Value *src, Value *isPoisoned, CallInst *CI, int operandPosition);
        void PoisonSI(Value *src, Value *isPoisoned, StoreInst *SI);
        void PoisonRetShadow(Value *src, Value *isPoisoned, ReturnInst *calleeRI);
        void PoisonMemsetDst(Value *src, Value *isSrcPoisoned, CallInst *MSI, Value *dstPtr, Value *setSize);
        static Value *stripCast(Value *v);
        void propagateShadow(Value *src);
        static bool isAnnotationIntrinsic(CallInst *CI);
        static std::string extractAnnotation(Value *annotationStrVal);
        static bool isSecureVersionMemTransferCI(CallInst *CI);
        static bool ContainWord(StringRef str, const std::string word);
        static bool ContainWordExactly(StringRef str, const std::string word);
        static bool isEncryptionFunction(Function *F);
        void poisonSensitiveGlobalVariableAtRuntime();
        void initializeCallbacks();
        void cleanStackObjectSensitiveShadow(Value *stackObject);
        void cleanStackObjectSensitiveShadow(SVF::ObjPN *objPN);
        Value *getStackOrHeapInstObjSize(Instruction *objI, IRBuilder<> &IRB);
        void dumpPts(SVF::PAGNode *PN);
        void dumpRevPts(SVF::PAGNode *PN);
        void pushAndPopArgShadowFrameAroundCallInst(CallInst *CI);
        static std::string toString(SVF::PAGNode *PN);
        static std::string toString(Value *val);
        static void dump(SVF::PAGNode *PN);
        void dump(SVF::NodeID nodeID);
        static void dump(Value *val);
        static StringRef SGXSanGetName(SVF::PAGNode *PN);
        void printStrAtRT(IRBuilder<> &IRB, std::string str);
        void printSrcAtRT(IRBuilder<> &IRB, Value *src);
        void collectHeapAllocators();
        void collectHeapAllocatorGlobalPtrs();
        bool isHeapAllocatorWrapper(Function &F);
        bool hasObjectNode(Value *val);
        void analyseModuleMetadata();
        void analyseDIType(DIType *type);
        DICompositeType *getDICompositeType(StructType *structTy);
        StructType *getStructTypeOfHeapObj(SVF::ObjPN *heapObj);
        bool isSensitive(StringRef str);
        bool mayBeSensitive(StringRef str);
        bool poisonStructSensitiveShadowOnTemp(DICompositeType *compositeTy, std::pair<uint8_t *, size_t> *shadowMaskPair, size_t offset);
        bool poisonSubfieldSensitiveShadowOnTemp(DIType *ty, std::pair<uint8_t *, size_t> *shadowBytesPair, size_t offset);
        void ShallowPoisonAlignedObject(Value *objPtr, Value *objSize, IRBuilder<> &IRB, std::pair<uint8_t *, size_t> *shadowBytesPair);
        SensitiveLevel getSensitiveLevel(StringRef str);
        StringRef getObjMeaningfulName(SVF::ObjPN *objPN);
        static bool isTBridgeFunc(Function &F);

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
            sgx_is_within_enclave,
            sgxsan_region_is_in_elrange_and_poisoned,
            PoisonSensitiveGlobal, Abort, SGXSanLog, print_ptr, print_arg, sgxsan_shallow_poison_object,
            sgxsan_check_shadow_bytes_match_obj, sgxsan_shallow_shadow_copy_on_mem_transfer, func_malloc_usable_size;

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
            plaintextKeywords = {"2encrypt", "unencrypt", "2seal", "unseal", "plain", "secret", "decrypt"},
            ciphertextKeywords = {"2decrypt", "undecrypt"},
            exactCiphertextKeywords = {"enc", "encrypt", "seal", "cipher"},
            inputKeywords = {"source", "input"},
            exactInputKeywords = {"src", "in"},
            exactSecretKeywords = {"key", "dec"};
        std::map<std::string, DICompositeType *> DICompositeTypeMap;
        std::unordered_set<DIType *> processedDITypes;
        size_t propagateCnt = 0;
    };
}
