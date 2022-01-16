#include "SensitiveLeakSan.hpp"
#include "SGXSanManifest.h"
#include "FunctionInstVisitor.hpp"

using namespace llvm;

#define SGXSAN_SENSITIVE_OBJ_FLAG 0x20

struct ShadowMapping
{
    int Scale;
    uint64_t Offset;
};

ShadowMapping Mapping = {3, SGXSAN_SHADOW_MAP_BASE};

Value *SensitiveLeakSan::memToShadow(Value *Shadow, IRBuilder<> &IRB)
{
    // as shadow memory only map elrange, let Shadow - EnclaveBase
    // EnclaveBase have to be initialied before here
    // check instrumentation is before poison operation
    LoadInst *SGXSanEnclaveBase = IRB.CreateLoad(IRB.getInt64Ty(), SGXSanEnclaveBaseAddr);
    setNoSanitizeMetadata(SGXSanEnclaveBase);

    Shadow = IRB.CreateSub(Shadow, SGXSanEnclaveBase);

    // Shadow >> scale
    Shadow = IRB.CreateLShr(Shadow, Mapping.Scale);
    if (Mapping.Offset == 0)
        return Shadow;

    // (Shadow >> scale) + offset
    Value *ShadowBase = IRB.getInt64(Mapping.Offset);

    return IRB.CreateAdd(Shadow, ShadowBase);
}

Value *SensitiveLeakSan::memToShadowPtr(Value *memPtr, IRBuilder<> &IRB)
{
    Value *memPtrInt = IRB.CreatePtrToInt(memPtr, IRB.getInt64Ty());
    Value *shadowPtrInt = memToShadow(memPtrInt, IRB);
    Value *shadowPtr = IRB.CreateIntToPtr(shadowPtrInt, IRB.getInt8PtrTy());
    return shadowPtr;
}

Value *SensitiveLeakSan::RoundUpUDiv(IRBuilder<> &IRB, Value *size, uint64_t dividend)
{
    return IRB.CreateUDiv(IRB.CreateAdd(size, IRB.getInt64(dividend - 1)), IRB.getInt64(dividend));
}

void SensitiveLeakSan::instrumentSensitivePoison(Instruction *objI, Value *objSize)
{
    Instruction *insertPt = objI->getNextNode();
    IRBuilder<> IRB(insertPt);

    Value *shadowAddr = memToShadowPtr(objI, IRB);
    objSize = IRB.CreateIntCast(objSize, IRB.getInt64Ty(), false);
    Value *shadowSpan = RoundUpUDiv(IRB, objSize, SHADOW_GRANULARITY);
    CallInst *memsetCI = IRB.CreateMemSet(shadowAddr, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG), shadowSpan, MaybeAlign());
    setNoSanitizeMetadata(memsetCI);
}

Value *SensitiveLeakSan::getSensitiveObjSize(Value *obj)
{
    if (AllocaInst *AI = dyn_cast<AllocaInst>(obj))
    {
        Type *objTy = AI->getAllocatedType();
        TypeSize size = M->getDataLayout().getTypeAllocSize(objTy);
        IRBuilder<> IRB(*C);
        return IRB.getInt64(size.getFixedSize());
    }
    else if (CallInst *CI = dyn_cast<CallInst>(obj))
    {
        if (Function *callee = CI->getCalledFunction())
        {
            StringRef calleeName = callee->getName();
            if (calleeName.equals("_Znwm") || calleeName.equals("malloc") ||
                calleeName.equals("calloc"))
            {
                return CI->getArgOperand(0);
            }
            else if (calleeName.equals("realloc"))
            {
                return CI->getArgOperand(1);
            }
        }
    }
    return nullptr;
}

std::string SensitiveLeakSan::extractAnnotation(Value *annotationStrVal)
{
    GlobalVariable *GV = nullptr;
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(annotationStrVal))
    {
        if (CE->getOpcode() == Instruction::GetElementPtr)
        {
            GV = dyn_cast<GlobalVariable>(CE->getOperand(0));
        }
    }
    else if (Instruction *I = dyn_cast<Instruction>(annotationStrVal))
    {
        if (I->getOpcode() == Instruction::GetElementPtr)
        {
            GV = dyn_cast<GlobalVariable>(I->getOperand(0));
        }
    }

    std::string annotation = "";
    if (GV)
    {
        Constant *initializer = GV->getInitializer();
        if (ConstantDataSequential *seq = dyn_cast<ConstantDataSequential>(initializer))
        {
            if (seq->isString())
            {
                annotation = seq->getAsString().str().c_str();
            }
        }
    }
    return annotation;
}

void SensitiveLeakSan::add2SensitiveObjAndPoison(Value *obj)
{
    auto emplaceResult = SensitiveObjs.emplace(obj);
    if (emplaceResult.second)
    {
        if (Instruction *objI = dyn_cast<Instruction>(obj))
        {
            Value *objSize = getSensitiveObjSize(obj);
            assert(objSize != nullptr);
            instrumentSensitivePoison(objI, objSize);
        }
        // TODO: non-instruction obj like global variable need to be poisoned at runtime
    }
}

int SensitiveLeakSan::getPointerLevel(Value *ptr)
{
    int level = 0;
    Type *type = ptr->getType();
    while (PointerType *ptrTy = dyn_cast<PointerType>(type))
    {
        level++;
        type = ptrTy->getElementType();
    }
    return level;
}

Value *SensitiveLeakSan::stripCast(Value *v)
{
    Value *value = v;
    while (CastInst *castI = dyn_cast<CastInst>(value))
    {
        value = castI->getOperand(0);
    }
    return value;
}

void SensitiveLeakSan::getNonPointerObjs(Value *ptr, std::unordered_set<Value *> &objs)
{
    std::unordered_set<Value *> svfObjs;
    // svfObjs contain memobjs and may contain pointer's memobjs
    getSVFPtObjs(ptr, svfObjs);
    for (auto obj : svfObjs)
    {
        if (getPointerLevel(obj) == 1)
        {
            // 1-level pointer point to memobj
            // e.g. '%a = alloca i8'
            // where %a is 'i8*' type, and memobj is 'i8' type
            objs.emplace(obj);
        }
        else
        {
            for (auto user : obj->users())
            {
                Value *stripedCastUser = stripCast(user);
                if (getPointerLevel(user) != getPointerLevel(stripedCastUser))
                {
                    // pointer's level changed
                    continue;
                }
                if (StoreInst *SI = dyn_cast<StoreInst>(user))
                {
                    Value *src = SI->getOperand(0);
                    src = stripCast(src);
                    if (CallInst *CI = dyn_cast<CallInst>(src))
                    {
                        Function *callee = CI->getCalledFunction();
                        if (callee)
                        {
                            StringRef calleeName = callee->getName();
                            if (calleeName.equals("_Znwm" /* new in cpp */) ||
                                calleeName.equals("malloc") || calleeName.equals("calloc") ||
                                calleeName.equals("realloc"))
                            {
                                objs.emplace(CI);
                            }
                        }
                    }
                }
            }
        }
    }
}

void SensitiveLeakSan::pushSensitiveObj(Value *annotatedPtr, Value *annotationStr)
{
    std::string annotation = extractAnnotation(annotationStr);
    if (annotation == "SGXSAN_SENSITIVE")
    {
        std::unordered_set<llvm::Value *> objSet;
        getNonPointerObjs(annotatedPtr, objSet);
        assert(objSet.size() <= 1);
        for (auto obj : objSet)
        {
            add2SensitiveObjAndPoison(obj);
        }
    }
}

bool SensitiveLeakSan::is_llvm_var_annotation_intrinsic(CallInst *CI)
{
    assert(CI != nullptr);
    Function *callee = CI->getCalledFunction();
    if (callee)
    {
        StringRef funcName = callee->getName();
        if (funcName.equals("llvm.var.annotation"))
        {
            return true;
        }
    }
    return false;
}

void SensitiveLeakSan::collectAndPoisonSensitiveObj(Module &M)
{
    // if (GlobalVariable *globalAnnotation = M.getGlobalVariable("llvm.global.annotations"))
    // {
    //     for (Value *GAOp : globalAnnotation->operands())
    //     {
    //         ConstantArray *CA = cast<ConstantArray>(GAOp);
    //         for (Value *CAOp : CA->operands())
    //         {
    //             ConstantStruct *CS = cast<ConstantStruct>(CAOp);
    //             Value *annotatedVar = CS->getOperand(0);
    //             ConstantExpr *CE = dyn_cast<ConstantExpr>(annotatedVar);
    //             while (CE && CE->getOpcode() == Instruction::BitCast)
    //             {
    //                 annotatedVar = CE->getOperand(0);
    //                 CE = dyn_cast<ConstantExpr>(annotatedVar);
    //             }
    //             pushSensitiveObj(annotatedVar, CS->getOperand(1));
    //         }
    //     }
    // }
    for (auto &F : M)
        for (auto &BB : F)
            for (auto &I : BB)
            {
                CallInst *CI = dyn_cast<CallInst>(&I);
                if (CI && is_llvm_var_annotation_intrinsic(CI))
                {
                    Value *annotatedPtr = CI->getOperand(0),
                          *annotateStr = CI->getArgOperand(1);
                    assert(isa<PointerType>(annotatedPtr->getType()));
                    pushSensitiveObj(annotatedPtr, annotateStr);
                }
            }
}

void SensitiveLeakSan::includeElrange()
{
    IRBuilder<> IRB(*C);

    SGXSanEnclaveBaseAddr = cast<GlobalVariable>(M->getOrInsertGlobal("g_enclave_base", IRB.getInt64Ty()));
    SGXSanEnclaveBaseAddr->setLinkage(GlobalValue::ExternalLinkage);

    SGXSanEnclaveSizeAddr = cast<GlobalVariable>(M->getOrInsertGlobal("g_enclave_size", IRB.getInt64Ty()));
    SGXSanEnclaveSizeAddr->setLinkage(GlobalValue::ExternalLinkage);
}

void SensitiveLeakSan::initSVF()
{
    svfModule = SVF::LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(*M);
    SVF::PAGBuilder builder;

    pag = builder.build(svfModule);
    ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);
    callgraph = ander->getPTACallGraph();
}

void SensitiveLeakSan::includeThreadFuncArgShadow()
{
    IRBuilder<> IRB(*C);

    poison_thread_func_arg_shadow_stack = M->getOrInsertFunction("poison_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty(), IRB.getInt64Ty());
    unpoison_thread_func_arg_shadow_stack = M->getOrInsertFunction("unpoison_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty(), IRB.getInt64Ty());
    onetime_query_thread_func_arg_shadow_stack = M->getOrInsertFunction("onetime_query_thread_func_arg_shadow_stack", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty());
    query_thread_func_arg_shadow_stack = M->getOrInsertFunction("query_thread_func_arg_shadow_stack", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty());
    clear_thread_func_arg_shadow_stack = M->getOrInsertFunction("clear_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty());
    push_thread_func_arg_shadow_stack = M->getOrInsertFunction("push_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty());
    pop_thread_func_arg_shadow_stack = M->getOrInsertFunction("pop_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty());
}

void SensitiveLeakSan::includeSGXSanCheck()
{
    IRBuilder<> IRB(*C);
    sgxsan_region_is_poisoned = M->getOrInsertFunction("sgxsan_region_is_poisoned", IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty());
    is_addr_in_elrange = M->getOrInsertFunction("is_addr_in_elrange", IRB.getInt1Ty(), IRB.getInt64Ty());
    is_addr_in_elrange_ex = M->getOrInsertFunction("is_addr_in_elrange_ex", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty());
    sgxsan_region_is_in_elrange_and_poisoned = M->getOrInsertFunction("sgxsan_region_is_in_elrange_and_poisoned", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty());
}

SensitiveLeakSan::SensitiveLeakSan(Module &ArgM)
{
    this->M = &ArgM;
    C = &(M->getContext());
    includeThreadFuncArgShadow();
    includeElrange();
    includeSGXSanCheck();
    initSVF();
}

StringRef SensitiveLeakSan::getBelongedFunctionName(Value *val)
{
    Function *func = nullptr;
    if (Instruction *I = dyn_cast<Instruction>(val))
        func = I->getFunction();
    else if (Argument *arg = dyn_cast<Argument>(val))
        func = arg->getParent();
    else
        abort();
    return func->getName();
}

void SensitiveLeakSan::getSVFOneLevelPtrs(Value *obj, std::unordered_set<Value *> &oneLevelPtrs)
{
    SVF::NodeID nodeID = pag->getObjectNode(obj);
    const SVF::NodeBS revPts = ander->getRevPts(nodeID);
    for (auto revPt : revPts)
    {
        SVF::PAGNode *node = pag->getPAGNode(revPt);
        if (isa<SVF::ValPN>(node) && !isa<SVF::DummyValPN>(node))
        {
            Value *ptr = const_cast<Value *>(node->getValue());
            if (ptr->getType() == obj->getType())
            {
                oneLevelPtrs.emplace(ptr);
            }
        }
    }
}

bool SensitiveLeakSan::runOnModule()
{

    collectAndPoisonSensitiveObj(*M);

    for (auto obj : SensitiveObjs)
        obj->dump();

    WorkList = this->SensitiveObjs;
    while (!WorkList.empty())
    {
        // update work status
        Value *work = *WorkList.begin();
        WorkList.erase(WorkList.begin());
        ProcessedList.emplace(work);

        std::unordered_set<Value *> ptr_set;
        getSVFOneLevelPtrs(work, ptr_set);

        errs() << "============== Show point-to set ==============\n";
        errs() << getBelongedFunctionName(work) << "\t";
        work->dump();
        errs() << "-----------------------------------------------\n";
        for (auto ptr : ptr_set)
        {
            errs() << getBelongedFunctionName(ptr) << "\t";
            ptr->dump();
        }
        errs() << "========== End of showing point-to set ==========\n";

        for (auto ptr : ptr_set)
        {
            doVFA(ptr);
        }
    }
    return true;
}

int SensitiveLeakSan::getCallInstOperandPosition(CallInst *CI, Value *operand)
{
    for (unsigned int i = 0; i < CI->getNumOperands(); i++)
    {
        if (CI->getOperand(i) == operand)
        {
            return i;
        }
    }
    return -1;
}

int SensitiveLeakSan::getFuncArgPosition(Argument *arg)
{
    Function *func = arg->getParent();
    for (unsigned int i = 0; i < func->arg_size(); i++)
    {
        if (func->getArg(i) == arg)
        {
            return i;
        }
    }
    return -1;
}

void SensitiveLeakSan::getDirectAndIndirectCalledFunction(CallInst *CI, SmallVector<Function *> &calleeVec)
{
    Function *callee = CI->getCalledFunction();
    if (callee == nullptr)
    {
        // it's an indirect call
        for (auto indCall : callgraph->getIndCallMap())
        {
            if (indCall.first->getCallSite() == CI)
            {
                for (auto svfCallee : indCall.second)
                {
                    calleeVec.push_back(svfCallee->getLLVMFun());
                }
            }
        }
    }
    else
    {
        // it's a direct call
        calleeVec.push_back(callee);
    }
}

Instruction *SensitiveLeakSan::findInstByName(Function *F, std::string InstName)
{
    for (auto &BB : *F)
    {
        for (auto &I : BB)
        {
            if (I.getName().str() == InstName)
            {
                return &I;
            }
        }
    }

    return nullptr;
}

void SensitiveLeakSan::setNoSanitizeMetadata(Instruction *I)
{
    unsigned int MDKindID = M->getMDKindID("nosanitize");
    MDNode *node = MDNode::get(*C, None);
    I->setMetadata(MDKindID, node);
}

// check directly with SGXSan shadow map
Value *SensitiveLeakSan::isLIPoisoned(LoadInst *LI)
{
    return isPtrPoisoned(LI, LI->getPointerOperand());
}

uint64_t SensitiveLeakSan::getTypeAllocaSize(Type *type)
{
    const DataLayout &DL = M->getDataLayout();
    TypeSize size = DL.getTypeAllocSize(type);
    return size.getFixedSize();
}

uint64_t SensitiveLeakSan::getPointerElementSize(Value *ptr)
{
    Type *type = ptr->getType();
    PointerType *ptrTy = cast<PointerType>(type);
    Type *elemTy = ptrTy->getElementType();
    return getTypeAllocaSize(elemTy);
}

Value *SensitiveLeakSan::isPtrPoisoned(Instruction *insertPoint, Value *ptr)
{
    assert(isa<PointerType>(ptr->getType()));
    IRBuilder<> IRB(insertPoint);
    return IRB.CreateCall(sgxsan_region_is_in_elrange_and_poisoned,
                          {IRB.CreatePtrToInt(ptr, IRB.getInt64Ty()),
                           IRB.getInt64(getPointerElementSize(ptr)),
                           IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
}

Value *SensitiveLeakSan::isArgPoisoned(Argument *arg)
{
    Instruction &firstFuncInsertPt = *arg->getParent()->getEntryBlock().getFirstInsertionPt();
    assert(&firstFuncInsertPt != nullptr);
    IRBuilder<> IRB(&firstFuncInsertPt);
    return IRB.CreateCall(query_thread_func_arg_shadow_stack,
                          {IRB.CreatePtrToInt(arg->getParent(), IRB.getInt64Ty()),
                           IRB.getInt64(getFuncArgPosition(arg))});
}

Value *SensitiveLeakSan::isCIRetPoisoned(CallInst *CI)
{
    Value *callee = CI->getCalledOperand();
    IRBuilder<> IRB(CI->getNextNode());
    CallInst *queryCI = IRB.CreateCall(query_thread_func_arg_shadow_stack,
                                       {IRB.CreatePtrToInt(callee, IRB.getInt64Ty()),
                                        IRB.getInt64(-1)});
    return queryCI;
}

Value *SensitiveLeakSan::instrumentPoisonCheck(Value *val)
{
    Value *isPoisoned = nullptr;
    if (poisonCheckedValues.count(val) == 0)
    {
        // never instrumented to check whether value is poisoned
        if (LoadInst *LI = dyn_cast<LoadInst>(val))
        {
            isPoisoned = isLIPoisoned(LI);
        }
        else if (Argument *arg = dyn_cast<Argument>(val))
        {
            isPoisoned = isArgPoisoned(arg);
        }
        else if (CallInst *CI = dyn_cast<CallInst>(val))
        {
            isPoisoned = isCIRetPoisoned(CI);
        }
        else
        {
            abort();
        }
        // record this source value has been checked whether is poisoned
        poisonCheckedValues[val] = isPoisoned;
    }
    else
    {
        // return records
        isPoisoned = poisonCheckedValues[val];
    }
    return isPoisoned;
}

void SensitiveLeakSan::PoisonCIOperand(Value *isPoisoned, CallInst *CI, int operandPosition)
{
    // instrument push/pop_thread_func_arg_shadow_stack around CI
    if (poisonedCI.count(CI) == 0)
    {
        // instrument push_thread_func_arg_shadow_stack
        IRBuilder<> IRB(CI);
        Value *callee = CI->getCalledOperand();
        Value *calleeAddrInt = IRB.CreatePtrToInt(callee, IRB.getInt64Ty());
        IRB.CreateCall(push_thread_func_arg_shadow_stack, calleeAddrInt);

        // instrument pop_thread_func_arg_shadow_stack
        Instruction *insertPointAfterCIRetCheck = CI->getNextNode();
        // we must instrument pop_thread_func_arg_shadow_stack(callee) behind query_thread_func_arg_shadow_stack(callee,-1)
        for (Instruction *nextInst = CI->getNextNode(); nextInst; nextInst = nextInst->getNextNode())
        {
            if (CallInst *nextCI = dyn_cast<CallInst>(nextInst))
            {
                if (nextCI->getCalledOperand() == query_thread_func_arg_shadow_stack.getCallee() &&
                    nextCI->getOperand(1) == IRB.getInt64(-1) &&
                    stripCast(nextCI->getOperand(0)) == stripCast(callee))
                {
                    insertPointAfterCIRetCheck = nextCI->getNextNode();
                }
                break;
            }
        }
        IRB.SetInsertPoint(insertPointAfterCIRetCheck);
        IRB.CreateCall(pop_thread_func_arg_shadow_stack, calleeAddrInt);

        // record this CI has been instrumented with push/pop_thread_func_arg_shadow_stack
        poisonedCI.emplace(CI, std::unordered_set<int>{});
    }

    // instrument to poison argument shadow
    if (poisonedCI[CI].count(operandPosition) == 0)
    {
        IRBuilder<> IRB(CI);
        Value *callee = CI->getCalledOperand();
        Value *calleeAddrInt = IRB.CreatePtrToInt(callee, IRB.getInt64Ty());
        Instruction *poisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, CI, false);
        IRB.SetInsertPoint(poisonedTerm);
        IRB.CreateCall(poison_thread_func_arg_shadow_stack, {calleeAddrInt, IRB.getInt64(operandPosition)});
        // record this argument's shadow has been poisoned
        poisonedCI[CI].emplace(operandPosition);
    }
}

uint64_t SensitiveLeakSan::RoundUpUDiv(uint64_t dividend, uint64_t divisor)
{
    return (dividend + divisor - 1) / divisor;
}

void SensitiveLeakSan::PoisonSI(Value *isPoisoned, StoreInst *SI)
{
    if (poisonedInst.count(SI) == 0)
    {
        Instruction *srcIsPoisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, SI, false);

        IRBuilder<> IRB(srcIsPoisonedTerm);
        Value *dstPtr = SI->getPointerOperand();
        CallInst *isDestInElrange = IRB.CreateCall(is_addr_in_elrange_ex,
                                                   {IRB.CreatePtrToInt(dstPtr, IRB.getInt64Ty()),
                                                    IRB.getInt64(getPointerElementSize(dstPtr))});

        Instruction *destIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, srcIsPoisonedTerm, false);

        IRB.SetInsertPoint(destIsInElrangeTerm);
        uint64_t dstMemSize = getTypeAllocaSize(SI->getValueOperand()->getType());
        CallInst *memsetCI = IRB.CreateMemSet(memToShadowPtr(dstPtr, IRB),
                                              IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG),
                                              IRB.getInt64(RoundUpUDiv(dstMemSize, SHADOW_GRANULARITY)),
                                              MaybeAlign());
        setNoSanitizeMetadata(memsetCI);
        poisonedInst.emplace(SI);
    }
}

void SensitiveLeakSan::PoisonRetShadow(Value *isPoisoned, ReturnInst *calleeRI)
{
    if (poisonedInst.count(calleeRI) == 0)
    {
        Instruction *isPoisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, calleeRI, false);
        IRBuilder<> IRB(isPoisonedTerm);
        IRB.CreateCall(poison_thread_func_arg_shadow_stack,
                       {IRB.CreatePtrToInt(calleeRI->getFunction(), IRB.getInt64Ty()),
                        IRB.getInt64(-1)});
        poisonedInst.emplace(calleeRI);
    }
}

void SensitiveLeakSan::getSVFPtObjs(Value *ptr, std::unordered_set<Value *> &objSet)
{
    assert(pag->hasValueNode(ptr));
    SVF::NodeID ptrNodeID = pag->getValueNode(ptr);
    const SVF::PointsTo &pts = ander->getPts(ptrNodeID);
    for (unsigned int pt : pts)
    {
        SVF::PAGNode *node = pag->getPAGNode(pt);
        if (isa<SVF::ObjPN>(node) && !isa<SVF::DummyObjPN>(node))
        {
            Value *nodeVal = const_cast<Value *>(node->getValue());
            objSet.emplace(nodeVal);
        }
    }
}

void SensitiveLeakSan::pushPtObj2WorkList(Value *ptr)
{
    if (pag->hasValueNode(ptr))
    {
        std::unordered_set<llvm::Value *> objSet;
        getSVFPtObjs(ptr, objSet);
        for (auto obj : objSet)
        {
            if (ProcessedList.count(obj) == 0)
                WorkList.emplace(obj);
        }
    }
}

void SensitiveLeakSan::propagateShadowInMemTransfer(CallInst *CI, Instruction *insertPoint, Value *destPtr, Value *srcPtr, Value *size)
{
    assert(CI != nullptr);
    if (processedMemTransferInst.count(CI) == 0)
    {
        // current memory transfer instruction has never been instrumented
        Value *isSrcPoisoned = isPtrPoisoned(insertPoint, srcPtr);

        Instruction *sourceIsPoisonedTerm = SplitBlockAndInsertIfThen(isSrcPoisoned, insertPoint, false);

        IRBuilder<> IRB(sourceIsPoisonedTerm);
        CallInst *isDestInElrange = IRB.CreateCall(is_addr_in_elrange_ex,
                                                   {IRB.CreatePtrToInt(destPtr, IRB.getInt64Ty()),
                                                    IRB.getInt64(getPointerElementSize(destPtr))});

        Instruction *dstIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, sourceIsPoisonedTerm, false);

        IRB.SetInsertPoint(dstIsInElrangeTerm);
        Instruction *memcpyCI = IRB.CreateMemCpy(memToShadowPtr(destPtr, IRB), MaybeAlign(),
                                                 memToShadowPtr(srcPtr, IRB), MaybeAlign(),
                                                 RoundUpUDiv(IRB, size, SHADOW_GRANULARITY));
        setNoSanitizeMetadata(memcpyCI);
        pushPtObj2WorkList(destPtr);
        // record this memory transfer CI has been instrumented
        processedMemTransferInst.emplace(CI);
    }
}

bool SensitiveLeakSan::isSecureVersionMemTransferCI(CallInst *CI)
{
    Function *callee = CI->getCalledFunction();
    if (callee)
    {
        StringRef calleeName = callee->getName();
        if (calleeName.equals("memcpy_s") ||
            calleeName.equals("memmove_s"))
        {
            return true;
        }
    }
    return false;
}

void SensitiveLeakSan::doVFA(Value *work)
{
    for (User *user : work->users())
    {
        if (LoadInst *LI = dyn_cast<LoadInst>(user))
        {
            propagateShadow(LI);
        }
        else if (CallInst *CI = dyn_cast<CallInst>(user))
        {
            MemTransferInst *MTI = dyn_cast<MemTransferInst>(user);
            if (MTI && MTI->getRawSource() == work)
            {
                propagateShadowInMemTransfer(MTI, MTI->getNextNode(), MTI->getDest(),
                                             MTI->getSource(), MTI->getOperand(2));
            }
            else if (isSecureVersionMemTransferCI(CI) && CI->getOperand(2) == work)
            {
                propagateShadowInMemTransfer(CI, CI->getNextNode(),
                                             CI->getOperand(0), CI->getOperand(2),
                                             CI->getOperand(1));
            }
        }
    }
}

void SensitiveLeakSan::propagateShadow(Value *src)
{
    // src maybe 'Function Argument'/LoadInst/'Return Value of CallInst'
    for (User *srcUser : src->users())
    {
        if (isa<StoreInst>(srcUser) || isa<CallInst>(srcUser) || isa<ReturnInst>(srcUser))
        {
            // there is a value flow, then check whether src is poisoned(at runtime)
            Value *isSrcPoisoned = instrumentPoisonCheck(src);
            if (StoreInst *SI = dyn_cast<StoreInst>(srcUser))
            {
                assert(SI->getValueOperand() == src);
                PoisonSI(isSrcPoisoned, SI);
                pushPtObj2WorkList(SI->getPointerOperand());
            }
            else if (CallInst *CI = dyn_cast<CallInst>(srcUser))
            {
                llvm::SmallVector<Function *> calleeVec;
                getDirectAndIndirectCalledFunction(CI, calleeVec);
                for (Function *callee : calleeVec)
                {
                    if (callee->isDeclaration())
                        continue;
                    StringRef calleeName = callee->getName();
                    if (calleeName.contains_lower("encrypt") ||
                        (calleeName.contains_lower("seal") && !calleeName.contains_lower("unseal")))
                        continue;
                    PoisonCIOperand(isSrcPoisoned, CI, getCallInstOperandPosition(CI, src));
                    propagateShadow(callee->getArg(getCallInstOperandPosition(CI, src)));
                }
            }
            else if (ReturnInst *RI = dyn_cast<ReturnInst>(srcUser))
            {
                assert(RI->getOperand(0) == src);
                Function *callee = RI->getFunction();
                for (auto callInstToCallGraphEdges : callgraph->getCallInstToCallGraphEdgesMap())
                {
                    for (auto callGraphEdge : callInstToCallGraphEdges.second)
                    {
                        if (callGraphEdge->getDstNode()->getFunction()->getLLVMFun() == callee)
                        {
                            CallInst *callerCI = cast<CallInst>(const_cast<Instruction *>(callInstToCallGraphEdges.first->getCallSite()));
                            PoisonRetShadow(isSrcPoisoned, RI);
                            propagateShadow(callerCI);
                        }
                    }
                }
            }
        }
    }
}
