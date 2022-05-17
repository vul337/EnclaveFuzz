#include "SensitiveLeakSan.hpp"
#include "SGXSanManifest.h"
#include "llvm/Demangle/Demangle.h"

using namespace llvm;

// #define DUMP_VALUE_FLOW
// #define SHOW_WORK_OBJ_PTS
#if (USE_SGXSAN_MALLOC)
#define MALLOC_USABLE_SZIE_STR "sgxsan_malloc_usable_size"
#else
// use our malloc series (which use dlmalloc as backend), and override original dlmalloc and tcmalloc libraries
#define MALLOC_USABLE_SZIE_STR "malloc_usable_size"
#endif

static cl::opt<int> heapAllocatorsMaxCollectionTimes(
    "heap-allocators-max-collection-times",
    cl::desc("max times of collection heap allocator wrappers"),
    cl::Hidden,
    cl::init(5));

#define SGXSAN_SENSITIVE_OBJ_FLAG 0x20

ShadowMapping Mapping = {3, SGXSAN_SHADOW_MAP_BASE};

Value *SensitiveLeakSan::memToShadow(Value *Shadow, IRBuilder<> &IRB)
{
    // as shadow memory only map elrange, let Shadow - EnclaveBase
    // EnclaveBase have to be initialied before here
    // check instrumentation is before poison operation
    LoadInst *SGXSanEnclaveBase = IRB.CreateLoad(IntptrTy, SGXSanEnclaveBaseAddr);
    setNoSanitizeMetadata(SGXSanEnclaveBase);

    Shadow = IRB.CreateSub(Shadow, SGXSanEnclaveBase);

    // Shadow >> scale
    Shadow = IRB.CreateLShr(Shadow, Mapping.Scale);
    if (Mapping.Offset == 0)
        return Shadow;

    // (Shadow >> scale) + offset
    Value *ShadowBase = ConstantInt::get(IntptrTy, Mapping.Offset);

    return IRB.CreateAdd(Shadow, ShadowBase);
}

Value *SensitiveLeakSan::memPtrToShadowPtr(Value *memPtr, IRBuilder<> &IRB)
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

void SensitiveLeakSan::ShallowPoisonAlignedObject(Value *objPtr, Value *objSize, IRBuilder<> &IRB, std::pair<uint8_t *, size_t> *srcShadowBytesPair)
{
    assert(objPtr->getType()->isPointerTy());
    auto objPtrInt = IRB.CreatePtrToInt(objPtr, IntptrTy);

    uint8_t *srcShadowBytesAddr = srcShadowBytesPair->first;
    size_t srcShadowBytesLen = srcShadowBytesPair->second;

    // use call to perform branch-like check to avoid change static alloca to dynamic alloca by mistake
    IRB.CreateCall(sgxsan_check_shadow_bytes_match_obj, {objPtrInt, objSize, ConstantInt::get(IntptrTy, srcShadowBytesLen)});

    Value *dstShadowAddrInt = memToShadow(objPtrInt, IRB);
    // Value *dstShadowSize = RoundUpUDiv(IRB, objSize, SHADOW_GRANULARITY);
    // Value *dstShadowSizeMinus1 = IRB.CreateSub(dstShadowSize, ConstantInt::get(IntptrTy, 1));

    size_t i = 0;
    for (; i < (srcShadowBytesLen - 1) / 4; i++)
    {
        // assume little-endian
        uint32_t value = (srcShadowBytesAddr[i * 4 + 3] << 24) + (srcShadowBytesAddr[i * 4 + 2] << 16) + (srcShadowBytesAddr[i * 4 + 1] << 8) + srcShadowBytesAddr[i * 4];
        auto storeShadow = IRB.CreateStore(
            IRB.getInt32(value),
            IRB.CreateIntToPtr(IRB.CreateAdd(dstShadowAddrInt, ConstantInt::get(IntptrTy, i * 4)), PointerType::get(IRB.getInt32Ty(), 0)));
        setNoSanitizeMetadata(storeShadow);
    }

    uint32_t endCopy = 0;
    size_t remained = srcShadowBytesLen - 1 - 4 * i;
    assert(remained < 4);
    for (size_t j = 0; j < remained; j++)
    {
        endCopy = (endCopy << 8) + srcShadowBytesAddr[4 * i + remained - 1 - j];
    }
    auto storeShadow = IRB.CreateStore(
        IRB.getInt32(endCopy),
        IRB.CreateIntToPtr(IRB.CreateAdd(dstShadowAddrInt, ConstantInt::get(IntptrTy, i * 4)), PointerType::get(IRB.getInt32Ty(), 0)));
    setNoSanitizeMetadata(storeShadow);

    if ((srcShadowBytesAddr[srcShadowBytesLen - 1] & (~0xF)) != 0)
    {
        Value *lastShadowBytePtr = IRB.CreateIntToPtr(IRB.CreateAdd(dstShadowAddrInt, ConstantInt::get(IntptrTy, srcShadowBytesLen - 1)), IRB.getInt8PtrTy());
        LoadInst *lastShadowByte = IRB.CreateLoad(lastShadowBytePtr);
        setNoSanitizeMetadata(lastShadowByte);

        Value *lastCopyVal = IRB.CreateAdd(IRB.getInt8(srcShadowBytesAddr[srcShadowBytesLen - 1] & (~0xF)), IRB.CreateAnd(lastShadowByte, IRB.getInt8(0xF)));
        StoreInst *lastSI = IRB.CreateStore(lastCopyVal, lastShadowBytePtr);
        setNoSanitizeMetadata(lastSI);
    }
}

void SensitiveLeakSan::poisonSensitiveStackOrHeapObj(SVF::ObjPN *objPN, std::pair<uint8_t *, size_t> *shadowBytesPair)
{
    assert(objPN);
    auto memObj = objPN->getMemObj();
    assert((memObj->isHeap() or memObj->isStack()) and not memObj->isFunction());

    Instruction *objI = cast<Instruction>(const_cast<Value *>(objPN->getValue()));
    SmallVector<Instruction *> objLivePoints;
    if (AllocaInst *objAI = dyn_cast<AllocaInst>(objI))
    {
        // TODO: extend at next time
        assert(shadowBytesPair == nullptr);
        auto AILifeTimeStart = SGXSanInstVisitor::visitFunction(*(objAI->getFunction())).AILifeTimeStart;
        for (auto start : AILifeTimeStart[objAI])
        {
            objLivePoints.push_back(start->getNextNode());
        }
        if (objLivePoints.size() == 0)
        {
            objLivePoints.push_back(objAI->getNextNode());
        }
    }
    else if (CallInst *objCI = dyn_cast<CallInst>(objI))
    {
        objLivePoints.push_back(objCI->getNextNode());
    }
    else
        abort();

    assert(objLivePoints.size() >= 1);

    IRBuilder<> IRB(objI->getNextNode());
    Value *obj = nullptr, *objSize = nullptr;
    if (SVF::GepObjPN *gepObjPN = dyn_cast<SVF::GepObjPN>(objPN))
    {
        auto inStructOffset = gepObjPN->getLocationSet().getOffset();
        obj = IRB.CreateGEP(objI, {IRB.getInt32(0), IRB.getInt32(inStructOffset)});
        auto _objSize = M->getDataLayout().getTypeAllocSize(cast<PointerType>(obj->getType())->getElementType());
        assert(_objSize > 0);
        objSize = IRB.getInt64(_objSize);
    }
    else if (isa<SVF::FIObjPN>(objPN))
    {
        obj = objI;
        objSize = getStackOrHeapInstObjSize(objI, IRB);
        assert(objSize != nullptr);
    }
    else
        abort();

    Value *objAddrInt = IRB.CreatePtrToInt(obj, IRB.getInt64Ty());

    for (auto insertPt : objLivePoints)
    {
        IRBuilder<> IRB(insertPt);
#ifdef DUMP_VALUE_FLOW
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr("\n-[Collect]->\n" + toString(objPN)),
                                   objAddrInt,
                                   objSize});
#endif
        if (shadowBytesPair)
        {
            ShallowPoisonAlignedObject(obj, objSize, IRB, shadowBytesPair);
        }
        else
        {
            IRB.CreateCall(sgxsan_shallow_poison_object, {objAddrInt, objSize, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG), IRB.getInt1(false)});
        }
    }
    cleanStackObjectSensitiveShadow(objPN);
}

Value *SensitiveLeakSan::getStackOrHeapInstObjSize(Instruction *objI, IRBuilder<> &IRB)
{
    Value *objSize = nullptr;
    if (AllocaInst *AI = dyn_cast<AllocaInst>(objI))
    {
        auto _objSize = getAllocaSizeInBytes(*AI);
        assert(_objSize > 0);
        objSize = IRB.getInt64(_objSize);
    }
    else if (CallInst *CI = dyn_cast<CallInst>(objI))
    {
        objSize = IRB.CreateIntCast(getHeapObjSize(CI, IRB), IRB.getInt64Ty(), false);
    }
    return objSize;
}

Value *SensitiveLeakSan::getHeapObjSize(CallInst *CI, IRBuilder<> &IRB)
{
    assert(CI->getFunctionType()->getReturnType()->isPointerTy());
    return IRB.CreateCall(func_malloc_usable_size, {IRB.CreatePointerCast(CI, IRB.getInt8PtrTy())});
    // std::string calleeName = demangle(getDirectCalleeName(CI).str());
    // if (calleeName.find("new") != std::string::npos || calleeName == "malloc")
    // {
    //     return CI->getArgOperand(0);
    // }
    // else if (calleeName == "realloc")
    // {
    //     return CI->getArgOperand(1);
    // }
    // else if (calleeName == "calloc")
    // {
    //     return IRB.CreateNUWMul(CI->getArgOperand(0), CI->getArgOperand(1));
    // }
    // else
    // {
    //     abort();
    // }

    // return nullptr;
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

bool SensitiveLeakSan::isTBridgeFunc(Function &F)
{
    auto CallInstVec = SGXSanInstVisitor::visitFunction(F).CallInstVec;
    for (auto CI : CallInstVec)
    {
        StringRef callee_name = getDirectCalleeName(CI);
        if (F.getName() == ("sgx_" /* ecall wrapper prefix */ + callee_name.str()))
        {
            return true;
        }
    }
    return false;
}

void SensitiveLeakSan::addAndPoisonSensitiveObj(SVF::ObjPN *objPN, std::pair<uint8_t *, size_t> *shadowBytesPair)
{
    assert(objPN);
    auto memObj = objPN->getMemObj();
    if (memObj->isHeap() or memObj->isStack())
    {
        auto parentFunc = cast<Instruction>(const_cast<Value *>(memObj->getRefVal()))->getFunction();
        if (isTBridgeFunc(*parentFunc))
            return;
    }
    auto emplaceResult = SensitiveObjs.emplace(objPN);
    if (emplaceResult.second)
    {
        if (memObj->isHeap() or memObj->isStack())
        {
            poisonSensitiveStackOrHeapObj(objPN, shadowBytesPair);
        }
        // Global variable need to be poisoned at runtime
        else if (memObj->isGlobalObj())
        {
            assert(not memObj->isFunction() && shadowBytesPair == nullptr);
            GlobalVariable *objGV = cast<GlobalVariable>(const_cast<Value *>(objPN->getValue()));
            uint64_t SizeInBytes = M->getDataLayout().getTypeAllocSize(objGV->getValueType());
            assert(SizeInBytes > 0);
            Constant *globalToBePolluted = ConstantStruct::get(
                StructType::get(IntptrTy, IntptrTy, Type::getInt8Ty(*C)),
                ConstantExpr::getPointerCast(objGV, IntptrTy),
                ConstantInt::get(IntptrTy, SizeInBytes),
                ConstantInt::get(Type::getInt8Ty(*C), SGXSAN_SENSITIVE_OBJ_FLAG));
            globalsToBePolluted.push_back(globalToBePolluted);
        }
        else
            abort();
    }
}

int SensitiveLeakSan::getPointerLevel(const Value *ptr)
{
    assert(ptr);
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

void SensitiveLeakSan::getNonPointerObjPNs(Value *value, std::unordered_set<SVF::ObjPN *> &objPNs)
{
    assert(value);
    if (isa<Function>(value))
        return;

    if (hasObjectNode(value))
    {
        auto objPNID = pag->getObjectNode(value);
        assert(pag->findPAGNode(objPNID));
        SVF::ObjPN *objPN = cast<SVF::ObjPN>(pag->getPAGNode(objPNID));
        getNonPointerObjPNs(objPN, objPNs);
    }
    else
    {
        assert(pag->hasValueNode(value));
        for (SVF::NodeID objPNID : ander->getPts(pag->getValueNode(value)))
        {
            assert(pag->findPAGNode(objPNID));
            SVF::ObjPN *objPN = cast<SVF::ObjPN>(pag->getPAGNode(objPNID));
            getNonPointerObjPNs(objPN, objPNs);
        }
    }
}

void SensitiveLeakSan::getNonPointerObjPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ObjPN *> &objPNs)
{
    assert(objPN);
    auto memObj = objPN->getMemObj();
    if (isa<SVF::DummyObjPN>(objPN) || memObj->isFunction())
        return;
    int pointerLevel = getPointerLevel(objPN->getValue());
    assert(pointerLevel >= 1);
    if (pointerLevel == 1)
    {
        if (isa<CallInst>(objPN->getValue()))
            assert(memObj->isHeap());
        objPNs.emplace(objPN);
    }
    else
    {
        // SVF models ConstantObj as special ObjPN#1, so there is no individual ObjPN for string constant etc..
        for (SVF::NodeID deepObjNodeID : ander->getPts(objPN->getId()))
        {
            assert(pag->findPAGNode(deepObjNodeID));
            SVF::ObjPN *deepObjPN = cast<SVF::ObjPN>(pag->getPAGNode(deepObjNodeID));
            if (isa<SVF::DummyObjPN>(deepObjPN) || deepObjPN->getMemObj()->isFunction())
                continue;
            assert(getPointerLevel(deepObjPN->getValue()) < pointerLevel);
            getNonPointerObjPNs(deepObjPN, objPNs);
        }
    }
}

void SensitiveLeakSan::pushSensitiveObj(Value *annotatedPtr)
{
    std::unordered_set<SVF::ObjPN *> objSet;
    getNonPointerObjPNs(annotatedPtr, objSet);
    assert(objSet.size() <= 1);
    for (auto obj : objSet)
    {
        addAndPoisonSensitiveObj(obj);
    }
}

bool SensitiveLeakSan::isAnnotationIntrinsic(CallInst *CI)
{
    assert(CI);
    auto calleeName = getDirectCalleeName(CI);
    return calleeName.contains("llvm") && calleeName.contains("annotation");
}

bool SensitiveLeakSan::ContainWord(StringRef str, const std::string word)
{
    std::string lowercaseWord = word;
    std::for_each(lowercaseWord.begin(), lowercaseWord.end(), [](char &c)
                  { c = std::tolower(c); });
    // underscore naming (lower case)
    if (str.contains(lowercaseWord))
        return true;
    std::string uppercaseWord = lowercaseWord;
    std::for_each(uppercaseWord.begin(), uppercaseWord.end(), [](char &c)
                  { c = std::toupper(c); });
    // underscore naming (upper case)
    if (str.contains(uppercaseWord))
        return true;
    std::string capitalWord = lowercaseWord;
    capitalWord[0] = std::toupper(capitalWord[0]);
    // Camel case naming
    return str.contains(capitalWord);
}

bool SensitiveLeakSan::ContainWordExactly(StringRef str, const std::string word)
{
    if (word == "")
        return true;
    else if (str == "")
        return false;
    // filter out non-alphanumeric
    std::regex nonAlphanumeric("[^0-9a-zA-Z]");
    if (std::regex_search(word, nonAlphanumeric))
    {
        errs() << "[ERROR] Word contain non-alphanumeric\n";
        abort();
    }

    std::regex wordRegex("([^0-9a-zA-Z]|^)" + word + "([^0-9a-zA-Z]|$)", std::regex_constants::icase);
    if (std::regex_search(str.str(), wordRegex))
        return true;
    // get lowercase word
    std::string lowercaseWord = word;
    std::for_each(lowercaseWord.begin(), lowercaseWord.end(), [](char &c)
                  { c = std::tolower(c); });
    // get capitalized word
    std::string capitalWord = lowercaseWord;
    capitalWord[0] = std::toupper(capitalWord[0]);
    // Camel case naming
    std::regex capitalWordRegex("(^" + lowercaseWord + "|" + capitalWord + ")([^0-9a-zA-Z]|[A-Z]|$)");
    return std::regex_search(str.str(), capitalWordRegex);
}

bool SensitiveLeakSan::isEncryptionFunction(Function *F)
{
    StringRef funcName = F->getName();
    return ((ContainWord(funcName, "encrypt") && !ContainWord(funcName, "decrypt") && !ContainWord(funcName, "encrypted")) ||
            (ContainWord(funcName, "seal") && !ContainWord(funcName, "unseal") && !ContainWord(funcName, "sealed")))
               ? true
               : false;
}

void SensitiveLeakSan::poisonSensitiveGlobalVariableAtRuntime()
{
    size_t N = globalsToBePolluted.size();
    if (N > 0)
    {
        PoisonSensitiveGlobalModuleCtor = createSanitizerCtor(*M, "PoisonSensitiveGlobalModuleCtor");
        IRBuilder<> IRB(PoisonSensitiveGlobalModuleCtor->getEntryBlock().getTerminator());

        ArrayType *ArrayOfGlobalStructTy =
            ArrayType::get(globalsToBePolluted[0]->getType(), N);
        auto AllGlobals = new GlobalVariable(
            *M, ArrayOfGlobalStructTy, false, GlobalVariable::InternalLinkage,
            ConstantArray::get(ArrayOfGlobalStructTy, globalsToBePolluted), "");

        IRB.CreateCall(PoisonSensitiveGlobal,
                       {IRB.CreatePointerCast(AllGlobals, IntptrTy),
                        ConstantInt::get(IntptrTy, N)});
        appendToGlobalCtors(*M, PoisonSensitiveGlobalModuleCtor, 103);
    }
}

DICompositeType *SensitiveLeakSan::getDICompositeType(StructType *structTy)
{
    if (structTy == nullptr)
        return nullptr;
    std::regex structPrefix("^struct\\.(.*)");
    std::smatch match;
    std::string structName = structTy->getName().str();
    if (std::regex_search(structName, match, structPrefix))
    {
        auto structName = match[1].str();
        auto result = DICompositeTypeMap.find(structName);
        if (result != DICompositeTypeMap.end())
        {
            return result->second;
        }
    }
    return nullptr;
}

StructType *SensitiveLeakSan::getStructTypeOfHeapObj(SVF::ObjPN *heapObjPN)
{
    assert(heapObjPN->getMemObj()->isHeap());
    CallInst *objCI = cast<CallInst>(const_cast<Value *>(heapObjPN->getValue()));
    assert(getPointerLevel(objCI) == 1);
    StructType *structTy = dyn_cast<StructType>(
        cast<PointerType>(objCI->getType())
            ->getElementType());
    if (!structTy)
    {
        CastInst *castI = dyn_cast<CastInst>(objCI->getNextNode());
        if (castI && castI->getOperand(0) == objCI)
        {
            assert(getPointerLevel(castI) == 1);
            structTy = dyn_cast<StructType>(
                cast<PointerType>(castI->getDestTy())
                    ->getElementType());
        }
    }
    return structTy;
}

SensitiveLevel SensitiveLeakSan::getSensitiveLevel(StringRef str)
{
    if (isSensitive(str))
        return IS_SENSITIVE;
    else if (mayBeSensitive(str))
        return MAY_BE_SENSITIVE;
    else
        return NOT_SENSITIVE;
}

bool SensitiveLeakSan::isSensitive(StringRef str)
{
    return (std::find_if(plaintextKeywords.begin(), plaintextKeywords.end(), [&](std::string keyword)
                         { return ContainWord(str, keyword); }) != plaintextKeywords.end() ||
            std::find_if(exactSecretKeywords.begin(), exactSecretKeywords.end(), [&](std::string keyword)
                         { return ContainWordExactly(str, keyword); }) != exactSecretKeywords.end()) &&
           not(
               std::find_if(ciphertextKeywords.begin(), ciphertextKeywords.end(), [&](std::string keyword)
                            { return ContainWord(str, keyword); }) != ciphertextKeywords.end() ||
               std::find_if(exactCiphertextKeywords.begin(), exactCiphertextKeywords.end(), [&](std::string keyword)
                            { return ContainWordExactly(str, keyword); }) != exactCiphertextKeywords.end());
}

bool SensitiveLeakSan::mayBeSensitive(StringRef str)
{
    return std::find_if(inputKeywords.begin(), inputKeywords.end(), [&](std::string keyword)
                        { return ContainWord(str, keyword); }) != inputKeywords.end() ||
           std::find_if(exactInputKeywords.begin(), exactInputKeywords.end(), [&](std::string keyword)
                        { return ContainWordExactly(str, keyword); }) != exactInputKeywords.end();
}

bool SensitiveLeakSan::poisonSubfieldSensitiveShadowOnTemp(DIType *ty, std::pair<uint8_t *, size_t> *shadowBytesPair, size_t offset)
{
    if (auto derivedTy = dyn_cast<DIDerivedType>(ty))
    {
        assert(derivedTy->getTag() == dwarf::DW_TAG_member);
        auto memOffset = derivedTy->getOffsetInBits();
        if (auto baseTy = derivedTy->getBaseType())
        {
            auto _ty = dyn_cast<DIDerivedType>(baseTy);
            while (_ty && _ty->getTag() == dwarf::DW_TAG_typedef)
            {
                baseTy = _ty->getBaseType();
                _ty = baseTy ? dyn_cast<DIDerivedType>(baseTy) : nullptr;
            }
            if (baseTy)
            {
                auto memCompositeType = dyn_cast<DICompositeType>(baseTy);
                if (memCompositeType && memCompositeType->getTag() == dwarf::DW_TAG_structure_type)
                    return poisonStructSensitiveShadowOnTemp(memCompositeType, shadowBytesPair, memOffset + offset);
            }
        }
    }
    return false;
}

bool SensitiveLeakSan::poisonStructSensitiveShadowOnTemp(DICompositeType *compositeTy, std::pair<uint8_t *, size_t> *shadowBytesPair, size_t offset)
{
    if (compositeTy->getTag() != dwarf::DW_TAG_structure_type)
        return false;
    bool hasPoisonedSensitive = false;
    for (auto ele : compositeTy->getElements())
    {
        auto *eleTy = cast<DIType>(ele);
        if (isSensitive(eleTy->getName()))
        {
            if (poisonSubfieldSensitiveShadowOnTemp(eleTy, shadowBytesPair, offset) == false)
            {
                size_t startBit = eleTy->getOffsetInBits() + offset;
                size_t endBit = startBit + eleTy->getSizeInBits() - 1;
                assert(endBit >= startBit);
                size_t startShadowByte = startBit / (8 * SHADOW_GRANULARITY);
                size_t endShadowByte = endBit / (8 * SHADOW_GRANULARITY);
                assert(endShadowByte <= shadowBytesPair->second);
                memset(shadowBytesPair->first + startShadowByte, SGXSAN_SENSITIVE_OBJ_FLAG, endShadowByte - startShadowByte + 1);
            }
            hasPoisonedSensitive = true;
        }
        else
        {
            hasPoisonedSensitive = hasPoisonedSensitive || poisonSubfieldSensitiveShadowOnTemp(eleTy, shadowBytesPair, offset);
        }
    }
    return hasPoisonedSensitive;
}

void SensitiveLeakSan::addAndPoisonSensitiveObj(SVF::ObjPN *objPN, SensitiveLevel sensitiveLevel)
{
    if (sensitiveLevel == IS_SENSITIVE)
    {
        addAndPoisonSensitiveObj(objPN);
    }
    else if (sensitiveLevel == MAY_BE_SENSITIVE)
    {
        if (objPN->getMemObj()->isHeap())
        {
            auto compositeTy = getDICompositeType(getStructTypeOfHeapObj(objPN));
            if (compositeTy && compositeTy->getSizeInBits() != 0 && compositeTy->getTag() == dwarf::DW_TAG_structure_type)
            {
                size_t shadowBytesLen = (compositeTy->getSizeInBits() + 8 * SHADOW_GRANULARITY - 1) / (8 * SHADOW_GRANULARITY);
                uint8_t shadowBytes[shadowBytesLen] = {0};
                std::pair<uint8_t *, size_t> shadowBytesPair(shadowBytes, shadowBytesLen);
                if (poisonStructSensitiveShadowOnTemp(compositeTy, &shadowBytesPair, 0))
                {
                    addAndPoisonSensitiveObj(objPN, &shadowBytesPair);
                    return;
                }
            }
        }
        addAndPoisonSensitiveObj(objPN);
    }
}

StringRef SensitiveLeakSan::getObjMeaningfulName(SVF::ObjPN *objPN)
{
    StringRef objName = SGXSanGetName(objPN);
    if (objPN->getMemObj()->isHeap())
    {
        auto obj = const_cast<Value *>(objPN->getValue());
        assert(isa<CallInst>(obj));
        for (auto user : getNonCastUsers(obj))
        {
            if (auto StoreI = dyn_cast<StoreInst>(user))
            {
                if (stripCast(StoreI->getValueOperand()) == obj)
                {
                    objName = ::SGXSanGetName(StoreI->getPointerOperand());
                    if (objName != "")
                        break;
                }
            }
        }
    }
    return objName;
}

void SensitiveLeakSan::addAndPoisonSensitiveObj(Value *obj)
{
    std::unordered_set<SVF::ObjPN *> objSet;
    getNonPointerObjPNs(obj, objSet);
    for (auto objPN : objSet)
    {
        auto objName = getObjMeaningfulName(objPN);
        if (objName != "")
        {
            addAndPoisonSensitiveObj(objPN, getSensitiveLevel(objName));
        }
    }
}

void SensitiveLeakSan::collectAndPoisonSensitiveObj()
{
    auto CallInstVec = SGXSanInstVisitor::visitModule(*M).CallInstVec;
    for (auto CI : CallInstVec)
    {
        SmallVector<Function *> calleeVec;
        getDirectAndIndirectCalledFunction(CI, calleeVec);
        for (auto callee : calleeVec)
        {
            if (isEncryptionFunction(callee))
            {
                if (callee->isDeclaration())
                {
                    for (unsigned int i = 0; i < CI->getNumArgOperands(); i++)
                    {
                        addAndPoisonSensitiveObj(CI->getArgOperand(i));
                    }
                }
                else
                {
                    for (Argument &arg : callee->args())
                    {
                        StringRef argName = ::SGXSanGetName(&arg);
                        if (argName != "" && getSensitiveLevel(argName) != NOT_SENSITIVE)
                        {
                            addAndPoisonSensitiveObj(CI->getArgOperand(arg.getArgNo()));
                        }
                    }
                }
            }
        }
    }

    if (GlobalVariable *globalAnnotation = M->getGlobalVariable("llvm.global.annotations"))
    {
        for (Value *GAOp : globalAnnotation->operands())
        {
            ConstantArray *CA = cast<ConstantArray>(GAOp);
            for (Value *CAOp : CA->operands())
            {
                ConstantStruct *CS = cast<ConstantStruct>(CAOp);
                std::string annotation = extractAnnotation(CS->getOperand(1));
                if (annotation == "SGXSAN_SENSITIVE")
                {
                    Value *annotatedVar = CS->getOperand(0);
                    ConstantExpr *CE = dyn_cast<ConstantExpr>(annotatedVar);
                    while (CE && CE->getOpcode() == Instruction::BitCast)
                    {
                        annotatedVar = CE->getOperand(0);
                        CE = dyn_cast<ConstantExpr>(annotatedVar);
                    }
                    pushSensitiveObj(annotatedVar);
                }
            }
        }
    }
    poisonSensitiveGlobalVariableAtRuntime();

    for (auto CI : CallInstVec)
    {
        if (isAnnotationIntrinsic(CI))
        {
            Value *annotatedPtr = CI->getOperand(0),
                  *annotateStr = CI->getArgOperand(1);
            assert(isa<PointerType>(annotatedPtr->getType()));
            std::string annotation = extractAnnotation(annotateStr);
            if (annotation == "SGXSAN_SENSITIVE")
            {
                pushSensitiveObj(annotatedPtr);
            }
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
    collectHeapAllocators();
    SVF::ExtAPI::getExtAPI()->registerDefinedFunc(heapAllocatorWrapperNames, SVF::ExtAPI::EFT_ALLOC);

    svfModule = SVF::LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(*M);
    SVF::PAGBuilder builder;

    pag = builder.build(svfModule);

    ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);
    callgraph = ander->getPTACallGraph();
    symInfo = SVF::SymbolTableInfo::SymbolInfo();
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
    sgx_is_within_enclave = M->getOrInsertFunction("sgx_is_within_enclave", IRB.getInt32Ty(), IRB.getInt8PtrTy(), IntptrTy);
    sgxsan_region_is_in_elrange_and_poisoned = M->getOrInsertFunction("sgxsan_region_is_in_elrange_and_poisoned", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty());
}

void SensitiveLeakSan::initializeCallbacks()
{
    IRBuilder<> IRB(*C);

    PoisonSensitiveGlobal = M->getOrInsertFunction(
        "PoisonSensitiveGlobal", IRB.getVoidTy(), IntptrTy, IntptrTy);
    Abort = M->getOrInsertFunction("abort", IRB.getVoidTy());
    Printf = M->getOrInsertFunction("sgxsan_printf", Type::getInt32Ty(*C), Type::getInt8PtrTy(*C), Type::getInt8PtrTy(*C));
    StrSpeicifier = IRB.CreateGlobalStringPtr("%s", "", 0, M);
    print_ptr = M->getOrInsertFunction("print_ptr", Type::getVoidTy(*C), Type::getInt8PtrTy(*C), Type::getInt64Ty(*C), Type::getInt64Ty(*C));
    print_arg = M->getOrInsertFunction("print_arg", Type::getVoidTy(*C), Type::getInt8PtrTy(*C), Type::getInt64Ty(*C), Type::getInt64Ty(*C));
    sgxsan_shallow_poison_object = M->getOrInsertFunction("sgxsan_shallow_poison_object", IRB.getVoidTy(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty(), IRB.getInt1Ty());
    sgxsan_check_shadow_bytes_match_obj = M->getOrInsertFunction("sgxsan_check_shadow_bytes_match_obj", IRB.getVoidTy(), IntptrTy, IntptrTy, IntptrTy);
    sgxsan_shallow_shadow_copy_on_mem_transfer = M->getOrInsertFunction("sgxsan_shallow_shadow_copy_on_mem_transfer", IRB.getVoidTy(), IntptrTy, IntptrTy, IntptrTy, IntptrTy);
    func_malloc_usable_size = M->getOrInsertFunction(MALLOC_USABLE_SZIE_STR, IRB.getInt64Ty(), IRB.getInt8PtrTy());
}

void SensitiveLeakSan::collectHeapAllocatorGlobalPtrs()
{
    for (GlobalVariable &GV : M->globals())
    {
        if (GV.hasInitializer())
        {
            Function *init = dyn_cast<Function>(GV.getInitializer());
            if (init && heapAllocators.count(init))
            {
                heapAllocatorGlobalPtrs.insert(&GV);
            }
        }
    }
}

// A function is a heap allocator wrapper if it allocates memory using malloc etc., and returns the same pointer.
bool SensitiveLeakSan::isHeapAllocatorWrapper(Function &F)
{
    // A heap allocator wrapper can have multiple allocator calls on different conditional branches as well as multiple return instructions
    std::vector<CallInst *> heapPtrs;
    if (!F.getFunctionType()->getReturnType()->isPointerTy())
        return false;

    auto &visitInfo = SGXSanInstVisitor::visitFunction(F);
    auto CallInstVec = visitInfo.CallInstVec;
    auto RetInstVec = visitInfo.ReturnInstVec;

    for (auto CallI : CallInstVec)
    {
        Function *calleeFunc = getCalledFunctionStripPointerCast(CallI);
        Value *calleeValue = CallI->getCalledOperand();
        // Direct call
        if (calleeFunc && heapAllocators.count(calleeFunc))
        {
            heapPtrs.push_back(CallI);
        }
        // Indirect call, then find if the function pointer is a global pointer that point to heap allocator
        else if (calleeFunc == nullptr)
        {
            if (LoadInst *LoadI = dyn_cast<LoadInst>(calleeValue))
            {
                // TODO: deal with uninitialized heapAllocatorGlobalPtr
                GlobalVariable *GV = dyn_cast<GlobalVariable>(LoadI->getPointerOperand());
                if (GV && heapAllocatorGlobalPtrs.count(GV))
                {
                    heapPtrs.push_back(CallI);
                }
            }
        }
    }

    // If this function doesn't call heap allocator
    if (heapPtrs.size() == 0)
    {
        return false;
    }

    // For all return instructions, check whether returned values are in heapPtrs
    for (ReturnInst *RetI : RetInstVec)
    {
        if (std::find_if(
                heapPtrs.begin(),
                heapPtrs.end(),
                [&](CallInst *heapPtr)
                { return AAResult->query(MemoryLocation(RetI->getOperand(0), MemoryLocation::UnknownSize), MemoryLocation(heapPtr, MemoryLocation::UnknownSize)); }) == heapPtrs.end())
        {
            return false;
        }
    }
    return true;
}

void SensitiveLeakSan::collectHeapAllocators()
{

    for (auto funcName : heapAllocatorBaseNames)
    {
        if (Function *func = M->getFunction(funcName))
        {
            heapAllocators.insert(func);
        }
    }

    for (int num = 0; num < heapAllocatorsMaxCollectionTimes; num++)
    {
        // Handle global function pointers
        collectHeapAllocatorGlobalPtrs();
        for (Function &F : *M)
        {
            if (!F.isDeclaration() && isHeapAllocatorWrapper(F))
            {
                heapAllocators.insert(&F);
            }
        }
    }
    for (auto heapAllocator : heapAllocators)
    {
        auto funcName = heapAllocator->getName().str();
        errs() << "[HeapAllocator] " << funcName << "\n";
        heapAllocatorNames.insert(funcName);
        if (heapAllocatorBaseNames.count(funcName) == 0)
        {
            heapAllocatorWrapperNames.insert(funcName);
        }
    }
}

void SensitiveLeakSan::analyseDIType(DIType *type)
{
    if (type == nullptr || processedDITypes.count(type) == 1)
        return;
    processedDITypes.insert(type);
    if (auto compositeTy = dyn_cast<DICompositeType>(type))
    {
        auto tyName = compositeTy->getName();
        if (tyName != "")
        {
            // errs() << "[Struct Name]" << tyName << "\n";
            DICompositeTypeMap[tyName.str()] = compositeTy;
        }
        auto tyIdName = compositeTy->getIdentifier();
        if (tyIdName != "")
        {
            // errs() << "[Struct Identifier]" << tyName << "\n";
            DICompositeTypeMap[tyIdName.str()] = compositeTy;
        }
        analyseDIType(compositeTy->getBaseType());
        for (auto ele : compositeTy->getElements())
        {
            if (ele == nullptr)
                continue;
            if (auto eleTy = dyn_cast<DIType>(ele))
                analyseDIType(eleTy);
        }
    }
    else if (auto derivedTy = dyn_cast<DIDerivedType>(type))
    {
        analyseDIType(derivedTy->getBaseType());
    }
    else if (auto subroutineTy = dyn_cast<DISubroutineType>(type))
    {
        for (auto paramTy : subroutineTy->getTypeArray())
            analyseDIType(paramTy);
    }
}

void SensitiveLeakSan::analyseModuleMetadata()
{
    if (auto dbg_cu = M->getNamedMetadata("llvm.dbg.cu"))
    {
        for (auto CU : dbg_cu->operands())
        {
            for (auto retainedType : cast<DICompileUnit>(CU)->getRetainedTypes())
            {
                if (auto type = dyn_cast<DIType>(retainedType))
                {
                    analyseDIType(type);
                }
                else
                {
                    abort();
                }
            }
        }
    }
}

SensitiveLeakSan::SensitiveLeakSan(Module &ArgM, CFLSteensAAResult &AAResult)
{
    M = &ArgM;
    this->AAResult = &AAResult;
    C = &(M->getContext());
    int LongSize = M->getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    includeThreadFuncArgShadow();
    includeElrange();
    includeSGXSanCheck();
    initializeCallbacks();
    initSVF();
    analyseModuleMetadata();
}

StringRef SensitiveLeakSan::getParentFuncName(SVF::PAGNode *node)
{
    if (node->hasValue())
    {
        Value *value = const_cast<Value *>(node->getValue());
        return ::getParentFuncName(value);
    }
    else
        return "";
}

void SensitiveLeakSan::getPtrValPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ValPN *> &ptrValPNs)
{
    for (SVF::NodeID ptrValPNID : ander->getRevPts(objPN->getId()))
    {
        if (not pag->findPAGNode(ptrValPNID))
            continue;
        SVF::PAGNode *node = pag->getPAGNode(ptrValPNID);
        if (SVF::ValPN *ptrValPN = SVF::SVFUtil::dyn_cast<SVF::ValPN>(node))
        {
            if (isa<SVF::DummyValPN>(ptrValPN))
                continue;
            if (getPointerLevel(ptrValPN->getValue()) == getPointerLevel(objPN->getValue()))
            {
                ptrValPNs.emplace(ptrValPN);
            }
        }
    }
}

int SensitiveLeakSan::getCallInstOperandPosition(CallInst *CI, Value *operand, bool rawOperand)
{
    for (unsigned int i = 0; i < CI->getNumOperands(); i++)
    {
        if (rawOperand ? (CI->getOperand(i) == operand) : (stripCast(CI->getOperand(i)) == operand))
        {
            return i;
        }
    }
    return -1;
}

void SensitiveLeakSan::getDirectAndIndirectCalledFunction(CallInst *CI, SmallVector<Function *> &calleeVec)
{
    Function *callee = getCalledFunctionStripPointerCast(CI);
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
            if (::SGXSanGetName(&I).str() == InstName)
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

uint64_t SensitiveLeakSan::getPointerElementSize(Value *ptr)
{
    Type *type = ptr->getType();
    PointerType *ptrTy = cast<PointerType>(type);
    Type *elemTy = ptrTy->getElementType();
    return M->getDataLayout().getTypeAllocSize(elemTy);
}

Value *SensitiveLeakSan::isPtrPoisoned(Instruction *insertPoint, Value *ptr, Value *size)
{
    assert(isa<PointerType>(ptr->getType()));
    auto ptrEleSize = getPointerElementSize(ptr);
    assert(ptrEleSize > 0);
    IRBuilder<> IRB(insertPoint);
    return IRB.CreateCall(sgxsan_region_is_in_elrange_and_poisoned,
                          {IRB.CreatePtrToInt(ptr, IRB.getInt64Ty()),
                           size ? IRB.CreateIntCast(size, IntptrTy, false) : IRB.getInt64(ptrEleSize),
                           IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
}

Value *SensitiveLeakSan::isArgPoisoned(Argument *arg)
{
    Instruction &firstFuncInsertPt = *arg->getParent()->begin()->begin();
    IRBuilder<> IRB(&firstFuncInsertPt);
    return IRB.CreateCall(query_thread_func_arg_shadow_stack,
                          {IRB.CreatePtrToInt(arg->getParent(), IRB.getInt64Ty()),
                           IRB.getInt64(arg->getArgNo())});
}

void SensitiveLeakSan::pushAndPopArgShadowFrameAroundCallInst(CallInst *CI)
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
        IRB.SetInsertPoint(CI->getNextNode());
        IRB.CreateCall(pop_thread_func_arg_shadow_stack, calleeAddrInt);

        // record this CI has been instrumented with push/pop_thread_func_arg_shadow_stack
        poisonedCI.emplace(CI, std::unordered_set<int>{});
    }
}

Value *SensitiveLeakSan::isCIRetPoisoned(CallInst *CI)
{
    pushAndPopArgShadowFrameAroundCallInst(CI);

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

void SensitiveLeakSan::printSrcAtRT(IRBuilder<> &IRB, Value *src)
{
    if (LoadInst *LI = dyn_cast<LoadInst>(src))
    {
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr("\n" + toString(LI)),
                                   IRB.CreatePtrToInt(LI->getPointerOperand(), IRB.getInt64Ty()),
                                   IRB.getInt64(M->getDataLayout().getTypeAllocSize(LI->getType()))});
    }
    else if (Argument *arg = dyn_cast<Argument>(src))
    {
        Value *funcAddrInt = IRB.CreatePtrToInt(arg->getParent(), IRB.getInt64Ty());
        auto pos = arg->getArgNo();
        IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr("\n" + toString(arg)), funcAddrInt, IRB.getInt64(pos)});
    }
    else if (CallInst *CI = dyn_cast<CallInst>(src))
    {
        Value *funcAddrInt = IRB.CreatePtrToInt(CI->getCalledOperand(), IRB.getInt64Ty());
        auto pos = -1;
        IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr("\n" + toString(CI)), funcAddrInt, IRB.getInt64(pos)});
    }
    else
    {
        abort();
    }
}

void SensitiveLeakSan::PoisonCIOperand(Value *src, Value *isPoisoned, CallInst *CI, int operandPosition)
{
    pushAndPopArgShadowFrameAroundCallInst(CI);

    // instrument to poison argument shadow
    if (poisonedCI[CI].count(operandPosition) == 0)
    {
        IRBuilder<> IRB(CI);
        Value *callee = CI->getCalledOperand();
        Value *calleeAddrInt = IRB.CreatePtrToInt(callee, IRB.getInt64Ty());
        Instruction *poisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, CI, false);
        IRB.SetInsertPoint(poisonedTerm);
#ifdef DUMP_VALUE_FLOW
        printSrcAtRT(IRB, src);
        printStrAtRT(IRB, "-[" + std::to_string(operandPosition) + "th Arg]->\n");
        IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr(toString(CI)), calleeAddrInt, IRB.getInt64(operandPosition)});
#endif
        IRB.CreateCall(poison_thread_func_arg_shadow_stack, {calleeAddrInt, IRB.getInt64(operandPosition)});
        // record this argument's shadow has been poisoned
        poisonedCI[CI].emplace(operandPosition);
    }
}

uint64_t SensitiveLeakSan::RoundUpUDiv(uint64_t dividend, uint64_t divisor)
{
    return (dividend + divisor - 1) / divisor;
}

void SensitiveLeakSan::printStrAtRT(IRBuilder<> &IRB, std::string str)
{
    IRB.CreateCall(Printf, {StrSpeicifier, IRB.CreateGlobalStringPtr(str)});
}

void SensitiveLeakSan::PoisonSI(Value *src, Value *isPoisoned, StoreInst *SI)
{
    if (poisonedInst.count(SI) == 0)
    {
        Instruction *srcIsPoisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, SI, false);

        IRBuilder<> IRB(srcIsPoisonedTerm);
        Value *dstPtr = SI->getPointerOperand();
        assert(not isa<Function>(dstPtr));
        auto dstPtrEleSize = getPointerElementSize(dstPtr);
        assert(dstPtrEleSize > 0);
        auto isDestInElrange = IRB.CreateICmpEQ(
            IRB.CreateCall(sgx_is_within_enclave, {IRB.CreatePointerCast(dstPtr, IRB.getInt8PtrTy()),
                                                   IRB.getInt64(dstPtrEleSize)}),
            IRB.getInt32(1));

        Instruction *destIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, srcIsPoisonedTerm, false);

        IRB.SetInsertPoint(destIsInElrangeTerm);
        uint64_t dstMemSize = M->getDataLayout().getTypeAllocSize(SI->getValueOperand()->getType());
        assert(dstPtrEleSize == dstMemSize);
        Value *dstMemSizeVal = IRB.getInt64(dstMemSize);
        Value *dstPtrInt = IRB.CreatePtrToInt(dstPtr, IRB.getInt64Ty());
#ifdef DUMP_VALUE_FLOW
        printSrcAtRT(IRB, src);
        printStrAtRT(IRB, "-[Store]->\n");
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr(toString(SI)), dstPtrInt, dstMemSizeVal});
#endif
        IRB.CreateCall(sgxsan_shallow_poison_object, {dstPtrInt, dstMemSizeVal, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG), IRB.getInt1(false)});
        cleanStackObjectSensitiveShadow(dstPtr);
        poisonedInst.emplace(SI);
    }
}

void SensitiveLeakSan::PoisonRetShadow(Value *src, Value *isPoisoned, ReturnInst *calleeRI)
{
    if (poisonedInst.count(calleeRI) == 0)
    {
        Instruction *isPoisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, calleeRI, false);
        IRBuilder<> IRB(isPoisonedTerm);
        Value *calleeAddrInt = IRB.CreatePtrToInt(calleeRI->getFunction(), IRB.getInt64Ty());
#ifdef DUMP_VALUE_FLOW
        printSrcAtRT(IRB, src);
        printStrAtRT(IRB, "-[Return]->\n");
        IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr(toString(calleeRI)), calleeAddrInt, IRB.getInt64(-1)});
#endif
        IRB.CreateCall(poison_thread_func_arg_shadow_stack, {calleeAddrInt, IRB.getInt64(-1)});
        poisonedInst.emplace(calleeRI);
    }
}

void SensitiveLeakSan::addPtObj2WorkList(Value *ptr)
{
    assert(ptr->getType()->isPointerTy());
    assert(getPointerLevel(ptr) == 1);
    assert(not isa<Function>(ptr));
    std::unordered_set<SVF::ObjPN *> objPNs;
    getNonPointerObjPNs(ptr, objPNs);
    for (auto objPN : objPNs)
    {
        if (ProcessedList.count(objPN) == 0)
            WorkList.emplace(objPN);
    }
}

// only process `AllocInst` stack object
void SensitiveLeakSan::cleanStackObjectSensitiveShadow(SVF::ObjPN *objPN)
{
    assert(objPN);
    if (objPN->hasValue())
    {
        AllocaInst *AI = dyn_cast<AllocaInst>(const_cast<Value *>(objPN->getValue()));
        // stack object must be a AllocInst
        if (AI && cleanedStackObjs.count(AI) == 0)
        {
            auto ReturnInstVec = SGXSanInstVisitor::visitFunction(*(AI->getFunction())).ReturnInstVec;
            for (ReturnInst *RI : ReturnInstVec)
            {
                IRBuilder<> IRB(RI);
                assert(AI->getAllocatedType()->isSized() && !AI->isSwiftError());
                auto _objSize = getAllocaSizeInBytes(*AI);
                assert(_objSize > 0);
                IRB.CreateCall(sgxsan_shallow_poison_object, {IRB.CreatePtrToInt(AI, IRB.getInt64Ty()),
                                                              IRB.getInt64(_objSize), IRB.getInt8(0x0), IRB.getInt1(true)});
            }
            cleanedStackObjs.emplace(AI);
        }
    }
}

bool SensitiveLeakSan::hasObjectNode(Value *val)
{
    return symInfo->objSyms().find(symInfo->getGlobalRep(val)) != symInfo->objSyms().end();
}

void SensitiveLeakSan::cleanStackObjectSensitiveShadow(Value *obj)
{

    assert(obj && !isa<Function>(obj));
    if (hasObjectNode(obj))
    {
        auto objPNID = pag->getObjectNode(obj);
        assert(pag->findPAGNode(objPNID));
        SVF::ObjPN *objPN = cast<SVF::ObjPN>(pag->getPAGNode(objPNID));
        cleanStackObjectSensitiveShadow(objPN);
    }
    else
    {
        // inter-procedure situation may have multi point-tos
        for (auto objPNID : ander->getPts(pag->getValueNode(obj)))
        {
            assert(pag->findPAGNode(objPNID));
            SVF::ObjPN *objPN = cast<SVF::ObjPN>(pag->getPAGNode(objPNID));
            // dump(objPN);
            cleanStackObjectSensitiveShadow(objPN);
        }
    }
}

void SensitiveLeakSan::propagateShadowInMemTransfer(CallInst *CI, Instruction *insertPoint, Value *destPtr, Value *srcPtr, Value *dstSize, Value *copyCnt)
{
    assert(CI != nullptr && not isa<Function>(destPtr));
    if (processedMemTransferInst.count(CI) == 0)
    {
        // current memory transfer instruction has never been instrumented

        IRBuilder<> IRB(insertPoint);

        copyCnt = IRB.CreateIntCast(copyCnt, IntptrTy, false);
        dstSize = IRB.CreateIntCast(dstSize, IntptrTy, false);
        // we have to avoid 0-size in mem transfer call
        auto sizeNot0 = IRB.CreateAnd(IRB.CreateICmpNE(dstSize, ConstantInt::get(IntptrTy, 0)), IRB.CreateICmpNE(copyCnt, ConstantInt::get(IntptrTy, 0)));
        Instruction *sizeNot0Term = SplitBlockAndInsertIfThen(sizeNot0, insertPoint, false);

        Value *isSrcPoisoned = isPtrPoisoned(sizeNot0Term, srcPtr, copyCnt);
        Instruction *sourceIsPoisonedTerm = SplitBlockAndInsertIfThen(isSrcPoisoned, sizeNot0Term, false);

        IRB.SetInsertPoint(sourceIsPoisonedTerm);
        auto isDestInElrange = IRB.CreateICmpEQ(
            IRB.CreateCall(sgx_is_within_enclave,
                           {IRB.CreatePointerCast(destPtr, IRB.getInt8PtrTy()), dstSize}),
            IRB.getInt32(1));
        Instruction *dstIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, sourceIsPoisonedTerm, false);

        IRB.SetInsertPoint(dstIsInElrangeTerm);
        Value *srcPtrInt = IRB.CreatePtrToInt(srcPtr, IntptrTy);
        Value *dstPtrInt = IRB.CreatePtrToInt(destPtr, IntptrTy);
#ifdef DUMP_VALUE_FLOW
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr("\n" + toString(srcPtr)),
                                   srcPtrInt, copyCnt});
        printStrAtRT(IRB, "-[Mem Transfer]->\n");
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr(toString(destPtr)),
                                   dstPtrInt, dstSize});
#endif
        IRB.CreateCall(sgxsan_shallow_shadow_copy_on_mem_transfer, {dstPtrInt, srcPtrInt, dstSize, copyCnt});

        addPtObj2WorkList(destPtr);
        cleanStackObjectSensitiveShadow(destPtr);
        // record this memory transfer CI has been instrumented
        processedMemTransferInst.emplace(CI);
    }
}

bool SensitiveLeakSan::isSecureVersionMemTransferCI(CallInst *CI)
{
    auto calleeName = getDirectCalleeName(CI);
    return calleeName == "memcpy_s" ||
           calleeName == "memmove_s";
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
                                             MTI->getSource(), MTI->getOperand(2), MTI->getOperand(2));
            }
            else if (isSecureVersionMemTransferCI(CI) && CI->getOperand(2) == work)
            {
                propagateShadowInMemTransfer(CI, CI->getNextNode(),
                                             CI->getOperand(0), CI->getOperand(2),
                                             CI->getOperand(1), CI->getOperand(3));
            }
            else
            {
                if (getDirectCalleeName(CI).contains("llvm.ptr.annotation"))
                {
                    doVFA(CI);
                }
            }
        }
    }
}

void SensitiveLeakSan::PoisonMemsetDst(Value *src, Value *isSrcPoisoned, CallInst *MSI, Value *dstPtr, Value *setSize)
{
    if (poisonedInst.count(MSI) == 0)
    {
        Instruction *srcIsPoisonedTerm = SplitBlockAndInsertIfThen(isSrcPoisoned, MSI, false);
        IRBuilder<> IRB(srcIsPoisonedTerm);
        assert(not isa<Function>(dstPtr));
        auto isDestInElrange = IRB.CreateICmpEQ(
            IRB.CreateCall(sgx_is_within_enclave,
                           {IRB.CreatePointerCast(dstPtr, IRB.getInt8PtrTy()), setSize}),
            IRB.getInt32(1));
        Instruction *destIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, srcIsPoisonedTerm, false);

        IRB.SetInsertPoint(destIsInElrangeTerm);
        Value *dstPtrInt = IRB.CreatePtrToInt(dstPtr, IRB.getInt64Ty());
#ifdef DUMP_VALUE_FLOW
        printSrcAtRT(IRB, src);
        printStrAtRT(IRB, "-[Memset]->\n");
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr(toString(MSI)), dstPtrInt, setSize});
#endif
        IRB.CreateCall(sgxsan_shallow_poison_object, {dstPtrInt, setSize, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG), IRB.getInt1(false)});
        cleanStackObjectSensitiveShadow(dstPtr);
        poisonedInst.emplace(MSI);
    }
}

void SensitiveLeakSan::propagateShadow(Value *src)
{
    // src maybe 'Function Argument'/LoadInst/'Return Value of CallInst'
    for (User *srcUser : getNonCastUsers(src))
    {
        if (isa<StoreInst>(srcUser) || isa<CallInst>(srcUser) || isa<ReturnInst>(srcUser))
        {
            // there is a value flow, then check whether src is poisoned(at runtime)
            Value *isSrcPoisoned = instrumentPoisonCheck(src);
            if (StoreInst *SI = dyn_cast<StoreInst>(srcUser))
            {
                assert(stripCast(SI->getValueOperand()) == src);
                PoisonSI(src, isSrcPoisoned, SI);
                addPtObj2WorkList(SI->getPointerOperand());
            }
            else if (CallInst *CI = dyn_cast<CallInst>(srcUser))
            {
                if (MemSetInst *MSI = dyn_cast<MemSetInst>(CI))
                {
                    if (stripCast(MSI->getArgOperand(1)) == src)
                    {
                        PoisonMemsetDst(src, isSrcPoisoned, MSI, MSI->getArgOperand(0), MSI->getArgOperand(2));
                        addPtObj2WorkList(MSI->getArgOperand(0));
                    }
                }
                else if (getDirectCalleeName(CI) == "memset_s")
                {
                    if (stripCast(CI->getArgOperand(2)) == src)
                    {
                        IRBuilder<> IRB(CI);
                        Value *setSize = IRB.CreateSelect(IRB.CreateICmpSLT(CI->getArgOperand(1), CI->getArgOperand(3)), CI->getArgOperand(1), CI->getArgOperand(3));
                        PoisonMemsetDst(src, isSrcPoisoned, CI, CI->getArgOperand(0), setSize);
                        addPtObj2WorkList(CI->getArgOperand(0));
                    }
                }
                else
                {
                    SmallVector<Function *> calleeVec;
                    getDirectAndIndirectCalledFunction(CI, calleeVec);
                    for (Function *callee : calleeVec)
                    {
                        if (callee->isDeclaration() || isEncryptionFunction(callee))
                            continue;
                        int opPos = getCallInstOperandPosition(CI, src);
                        assert(opPos != -1);
                        PoisonCIOperand(src, isSrcPoisoned, CI, opPos);
                        if (!callee->isVarArg())
                        {
                            auto arg = callee->getArg(opPos);
                            if (getPointerLevel(arg) == getPointerLevel(src))
                            {
                                propagateShadow(arg);
                            }
                        }
                    }
                }
            }
            else if (ReturnInst *RI = dyn_cast<ReturnInst>(srcUser))
            {
                assert(stripCast(RI->getOperand(0)) == src);
                Function *callee = RI->getFunction();
                for (auto callInstToCallGraphEdges : callgraph->getCallInstToCallGraphEdgesMap())
                {
                    for (auto callGraphEdge : callInstToCallGraphEdges.second)
                    {
                        if (callGraphEdge->getDstNode()->getFunction()->getLLVMFun() == callee)
                        {
                            CallInst *callerCI = cast<CallInst>(const_cast<Instruction *>(callInstToCallGraphEdges.first->getCallSite()));
                            PoisonRetShadow(src, isSrcPoisoned, RI);
                            propagateShadow(callerCI);
                        }
                    }
                }
            }
        }
    }
}

bool SensitiveLeakSan::runOnModule()
{
#ifdef DUMP_VALUE_FLOW
    for (auto &F : *M)
    {
        if (F.isDeclaration())
            continue;
        std::set<std::string> OCallsIgnore{"sgxsan_ocall_print_string", "sgxsan_ocall_addr2line", "sgxsan_ocall_addr2line_ex", "sgxsan_ocall_addr2func_name", "sgxsan_ocall_depcit_distribute", "sgxsan_ocall_init_shadow_memory", "sgxsan_ocall_get_mmap_infos"};
        StringRef func_name = F.getName();
        if (std::find(OCallsIgnore.begin(), OCallsIgnore.end(), func_name.str()) != OCallsIgnore.end())
            continue;
        IRBuilder<> IRB(&(F.front().front()));
        printStrAtRT(IRB, "[RUN FUNC] " + func_name.str() + " " + SVF::SVFUtil::getSourceLoc(&F.front().front()) + "\n");
    }
#endif
    collectAndPoisonSensitiveObj();

    for (auto objPN : SensitiveObjs)
    {
        dump(objPN);
    }

    WorkList = this->SensitiveObjs;
    while (!WorkList.empty())
    {
        // update work status
        SVF::ObjPN *workObjPN = *WorkList.begin();
        WorkList.erase(WorkList.begin());
        ProcessedList.emplace(workObjPN);

        std::unordered_set<SVF::ValPN *> ptrValPNs;
        getPtrValPNs(workObjPN, ptrValPNs);
#ifdef SHOW_WORK_OBJ_PTS
        errs() << "============== Show point-to set ==============\n";
        dump(workObjPN);
        errs() << "-----------------------------------------------\n";
#endif
        for (auto ptrValPN : ptrValPNs)
        {
#ifdef SHOW_WORK_OBJ_PTS
            dump(ptrValPN);
#endif
            auto ptrVal = const_cast<Value *>(ptrValPN->getValue());
            doVFA(ptrVal);
        }
#ifdef SHOW_WORK_OBJ_PTS
        errs() << "========= End of showing point-to set ==========\n";
#endif
    }
    return true;
}

void SensitiveLeakSan::dumpPts(SVF::PAGNode *PN)
{
    for (SVF::NodeID nodeID : ander->getPts(PN->getId()))
    {
        assert(pag->findPAGNode(nodeID));
        dump(pag->getPAGNode(nodeID));
    }
}

void SensitiveLeakSan::dumpRevPts(SVF::PAGNode *PN)
{
    for (SVF::NodeID nodeID : ander->getRevPts(PN->getId()))
    {
        if (pag->findPAGNode(nodeID))
        {
            dump(pag->getPAGNode(nodeID));
        }
    }
}

StringRef SensitiveLeakSan::SGXSanGetName(SVF::PAGNode *PN)
{
    if (PN->hasValue())
    {
        return ::SGXSanGetName(const_cast<Value *>(PN->getValue()));
    }
    else
        return "";
}

std::string SensitiveLeakSan::toString(SVF::PAGNode *PN)
{
    std::stringstream ss;
    ss << "[Func] " << getParentFuncName(PN).str() << " [Name] " << SGXSanGetName(PN).str() << " " << PN->toString();
    return ss.str();
}

void SensitiveLeakSan::dump(SVF::NodeID nodeID)
{
    assert(pag->findPAGNode(nodeID));
    dump(pag->getPAGNode(nodeID));
}

void SensitiveLeakSan::dump(SVF::PAGNode *PN)
{
    errs() << toString(PN) << "\n\n";
}

std::string SensitiveLeakSan::toString(Value *val)
{
    return ::toString(val) + " " + SVF::SVFUtil::getSourceLoc(val);
}

void SensitiveLeakSan::dump(Value *val)
{
    errs() << toString(val) << "\n\n";
}