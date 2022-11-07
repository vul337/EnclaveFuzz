#include "SensitiveLeakSanitizer.h"

#include "SGXSanPassConfig.h"
#include "nlohmann/json.hpp"
#include "llvm/Demangle/Demangle.h"
#include <filesystem>

using namespace llvm;
using ordered_json = nlohmann::ordered_json;
namespace fs = std::filesystem;

static cl::opt<int> ClHeapAllocatorsMaxCollectionTimes(
    "heap-allocators-max-collection-times",
    cl::desc("max times of collection heap allocator wrappers"), cl::Hidden,
    cl::init(5));

// #define DUMP_VALUE_FLOW
// #define SHOW_WORK_OBJ_PTS
const uint8_t kSGXSanSensitiveObjData = 0x20;

Value *SensitiveLeakSanitizer::memToShadow(Value *Shadow, IRBuilder<> &IRB) {
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
  if (Mapping.OrShadowOffset)
    return IRB.CreateOr(Shadow, ShadowBase);
  else
    return IRB.CreateAdd(Shadow, ShadowBase);
}

Value *SensitiveLeakSanitizer::memPtrToShadowPtr(Value *memPtr,
                                                 IRBuilder<> &IRB) {
  Value *memPtrInt = IRB.CreatePtrToInt(memPtr, IRB.getInt64Ty());
  Value *shadowPtrInt = memToShadow(memPtrInt, IRB);
  Value *shadowPtr = IRB.CreateIntToPtr(shadowPtrInt, IRB.getInt8PtrTy());
  return shadowPtr;
}

Value *SensitiveLeakSanitizer::RoundUpUDiv(IRBuilder<> &IRB, Value *size,
                                           uint64_t dividend) {
  return IRB.CreateUDiv(IRB.CreateAdd(size, IRB.getInt64(dividend - 1)),
                        IRB.getInt64(dividend));
}

void SensitiveLeakSanitizer::ShallowPoisonAlignedObject(
    Value *objAddrInt, Value *objSize, IRBuilder<> &IRB,
    std::pair<bool *, size_t> *sensitiveIndicator) {
  bool *indicatorArr = sensitiveIndicator->first;
  size_t indicatorSize = sensitiveIndicator->second;

  Value *shadowAddr = memToShadow(objAddrInt, IRB); /* IntptrTy */

  size_t step = 0, stepSize = M->getDataLayout().getPointerSizeInBits() / 8;
  for (; step < (indicatorSize - 1) / stepSize; step++) {
    // assume little-endian
    // get several kSGXSanSensitiveObjData concate
    uint64_t value = 0;
    for (size_t i = 1; i <= stepSize; i++) {
      value = (value << 8 /* bit */) + indicatorArr[(step + 1) * stepSize - i]
                  ? kSGXSanSensitiveObjData
                  : 0;
    }
    auto stepShadowAddr = IRB.CreateIntToPtr(
        IRB.CreateAdd(shadowAddr, ConstantInt::get(IntptrTy, step * stepSize)),
        IntptrTy->getPointerTo());
    LoadInst *loadStepShadowByte = IRB.CreateLoad(IntptrTy, stepShadowAddr);
    setNoSanitizeMetadata(loadStepShadowByte);
    auto oredShadowByte =
        IRB.CreateOr(loadStepShadowByte, ConstantInt::get(IntptrTy, value));
    auto storeStepShadowByte = IRB.CreateStore(oredShadowByte, stepShadowAddr);
    setNoSanitizeMetadata(storeStepShadowByte);
  }

  size_t remained = indicatorSize - stepSize * step;
  for (size_t i = 0; i < remained; i++) {
    if (indicatorArr[step * stepSize + i]) {
      auto remainedShadowAddr = IRB.CreateIntToPtr(
          IRB.CreateAdd(shadowAddr,
                        ConstantInt::get(IntptrTy, step * stepSize + i)),
          IntptrTy->getPointerTo());
      LoadInst *loadRemainedShadowByte =
          IRB.CreateLoad(IRB.getInt8Ty(), remainedShadowAddr);
      setNoSanitizeMetadata(loadRemainedShadowByte);
      auto oredShadowByte = IRB.CreateOr(loadRemainedShadowByte,
                                         IRB.getInt8(kSGXSanSensitiveObjData));
      StoreInst *storeRemainedShadowByte =
          IRB.CreateStore(oredShadowByte, remainedShadowAddr);
      setNoSanitizeMetadata(storeRemainedShadowByte);
    }
  }
}

void SensitiveLeakSanitizer::poisonSensitiveStackOrHeapObj(
    SVF::ObjVar *objPN, std::pair<bool *, size_t> *sensitiveIndicator) {
  assert(objPN);
  auto memObj = objPN->getMemObj();
  assert((memObj->isHeap() or memObj->isStack()) and not memObj->isFunction());

  // get object live points
  Instruction *objI = cast<Instruction>(const_cast<Value *>(objPN->getValue()));
  SmallVector<Instruction *> objLivePoints;
  if (AllocaInst *objAI = dyn_cast<AllocaInst>(objI)) {
    /// TODO: extend at next time
    assert(sensitiveIndicator == nullptr);
    auto AILifeTimeStart =
        SGXSanInstVisitor::visitFunction(*objAI->getFunction()).AILifeTimeStart;
    for (auto start : AILifeTimeStart[objAI]) {
      objLivePoints.push_back(start->getNextNode());
    }
    if (objLivePoints.size() == 0) {
      objLivePoints.push_back(objAI->getNextNode());
    }
  } else if (CallInst *objCI = dyn_cast<CallInst>(objI)) {
    objLivePoints.push_back(objCI->getNextNode());
  } else {
    abort();
  }
  assert(objLivePoints.size() >= 1);

  // get object address and size
  IRBuilder<> IRB(objI->getNextNode());
  Value *obj = nullptr, *objSize = nullptr;
  if (SVF::GepObjVar *gepObjPN = dyn_cast<SVF::GepObjVar>(objPN)) {
    auto ls = gepObjPN->getLocationSet();
    SmallVector<Value *> inStructOffset;
    if (ls.getOffsetValueVec().size()) {
      for (auto offset : ls.getOffsetValueVec())
        inStructOffset.push_back(const_cast<SVF::Value *>(offset.first));
    } else {
      inStructOffset.push_back(ConstantInt::get(Type::getInt32Ty(*C), 0));
      inStructOffset.push_back(ConstantInt::get(
          Type::getInt32Ty(*C), ls.accumulateConstantFieldIdx()));
    }

    obj =
        IRB.CreateGEP(objI->getType()->getScalarType()->getPointerElementType(),
                      objI, inStructOffset);
    size_t _objSize = M->getDataLayout().getTypeAllocSize(
        cast<PointerType>(obj->getType())->getElementType());
    assert(_objSize > 0);
    objSize = ConstantInt::get(IntptrTy, _objSize);
  } else if (isa<SVF::FIObjVar>(objPN)) {
    obj = objI;
    objSize = getStackOrHeapInstObjSize(objI);
    assert(objSize != nullptr);
  } else {
    abort();
  }
  Value *objAddrInt = IRB.CreatePtrToInt(obj, IntptrTy);

  // Shallow Poison Object
  for (auto insertPt : objLivePoints) {
    IRBuilder<> IRB(insertPt);
#ifdef DUMP_VALUE_FLOW
    IRB.CreateCall(PrintPtr, {IRB.CreateGlobalStringPtr("-[Collect]->\n" +
                                                        toString(objPN)),
                              objAddrInt, objSize});
#endif
    if (sensitiveIndicator) {
      ShallowPoisonAlignedObject(objAddrInt, objSize, IRB, sensitiveIndicator);
    } else {
      IRB.CreateCall(ShallowPoisonShadow,
                     {objAddrInt, objSize, IRB.getInt8(kSGXSanSensitiveObjData),
                      IRB.getInt1(true)});
    }
  }
  ShallowUnpoisonStackObj(objPN);
}

Value *SensitiveLeakSanitizer::getStackOrHeapInstObjSize(Instruction *objI) {
  Value *objSize = nullptr;
  if (AllocaInst *AI = dyn_cast<AllocaInst>(objI)) {
    size_t _objSize = getAllocaSizeInBytes(*AI);
    assert(_objSize > 0);
    objSize = ConstantInt::get(IntptrTy, _objSize);
  } else if (CallInst *CI = dyn_cast<CallInst>(objI)) {
    assert(CI->getFunctionType()->getReturnType()->isPointerTy());
    IRBuilder<> IRB(objI->getNextNode());
    objSize = IRB.CreateCall(
        MallocUsableSize, {IRB.CreatePointerCast(CI, Type::getInt8PtrTy(*C))});
  } else {
    abort();
  }
  return objSize;
}

std::string SensitiveLeakSanitizer::extractAnnotation(Value *annotationStrVal) {
  // get GV
  GlobalVariable *GV = nullptr;
  ConstantExpr *CE = dyn_cast<ConstantExpr>(annotationStrVal);
  if (CE && CE->getOpcode() == Instruction::GetElementPtr) {
    GV = dyn_cast<GlobalVariable>(CE->getOperand(0));
  } else if (GetElementPtrInst *GEPI =
                 dyn_cast<GetElementPtrInst>(annotationStrVal)) {
    GV = dyn_cast<GlobalVariable>(GEPI->getOperand(0));
  }

  // get annotation
  std::string annotation = "";
  if (GV) {
    Constant *initializer = GV->getInitializer();
    if (ConstantDataSequential *seq =
            dyn_cast<ConstantDataSequential>(initializer)) {
      if (seq->isString()) {
        annotation = seq->getAsString().str().c_str();
      }
    }
  }
  return annotation;
}

bool SensitiveLeakSanitizer::isTBridgeFunc(Function &F) {
  auto CallInstVec = SGXSanInstVisitor::visitFunction(F).CallInstVec;
  for (auto CI : CallInstVec) {
    StringRef callee_name = getDirectCalleeName(CI);
    if (F.getName() ==
        ("sgx_" /* ecall wrapper prefix */ + callee_name.str())) {
      return true;
    }
  }
  return false;
}

void SensitiveLeakSanitizer::addAndPoisonSensitiveObj(
    SVF::ObjVar *objPN, std::pair<bool *, size_t> *sensitiveIndicator) {
  assert(objPN);
  auto memObj = objPN->getMemObj();
  if (memObj->isHeap() or memObj->isStack()) {
    auto parentFunc = cast<Instruction>(const_cast<Value *>(memObj->getValue()))
                          ->getFunction();
    if (isTBridgeFunc(*parentFunc))
      return;
  }
  if (SensitiveObjs.emplace(objPN).second) {
    if (memObj->isHeap() or memObj->isStack()) {
      poisonSensitiveStackOrHeapObj(objPN, sensitiveIndicator);
    }
    // Global variable need to be poisoned at runtime
    else if (memObj->isGlobalObj()) {
      assert(not memObj->isFunction() && sensitiveIndicator == nullptr);
      GlobalVariable *objGV =
          cast<GlobalVariable>(const_cast<Value *>(objPN->getValue()));
      uint64_t SizeInBytes =
          M->getDataLayout().getTypeAllocSize(objGV->getValueType());
      assert(SizeInBytes > 0);
      Constant *globalToBePolluted =
          ConstantStruct::get(StructType::get(IntptrTy, IntptrTy),
                              ConstantExpr::getPointerCast(objGV, IntptrTy),
                              ConstantInt::get(IntptrTy, SizeInBytes));
      globalsToBePolluted.push_back(globalToBePolluted);
    } else
      abort();
  }
}

int SensitiveLeakSanitizer::getPointerLevel(const Value *ptr) {
  assert(ptr);
  int level = 0;
  Type *type = ptr->getType();
  while (PointerType *ptrTy = dyn_cast<PointerType>(type)) {
    level++;
    type = ptrTy->getElementType();
  }
  return level;
}

std::unordered_set<SVF::ObjVar *>
SensitiveLeakSanitizer::getTargetObj(Value *value) {
  std::unordered_set<SVF::ObjVar *> objVars;
  if (objSym->find(SVF::SVFUtil::getGlobalRep(value)) != objSym->end()) {
    objVars.emplace(
        cast<SVF::ObjVar>(pag->getGNode(pag->getObjectNode(value))));
  } else {
    for (auto objPNID : ander->getPts(pag->getValueNode(value))) {
      objVars.emplace(cast<SVF::ObjVar>(pag->getGNode(objPNID)));
    }
  }
  return objVars;
}

std::unordered_set<SVF::ObjVar *>
SensitiveLeakSanitizer::getNonPtrObjPNs(Value *value) {
  std::unordered_set<SVF::ObjVar *> dstObjPNs;
  assert(value);
  if (isa<Function>(value))
    return dstObjPNs;

  for (auto objPN : getTargetObj(value)) {
    dstObjPNs.merge(getNonPtrObjPNs(objPN));
  }
  return dstObjPNs;
}

std::unordered_set<SVF::ObjVar *>
SensitiveLeakSanitizer::getNonPtrObjPNs(SVF::ObjVar *objPN) {
  std::unordered_set<SVF::ObjVar *> objPNs;
  assert(objPN);
  auto memObj = objPN->getMemObj();
  if (isa<SVF::DummyObjVar>(objPN) || memObj->isFunction())
    return objPNs;
  int pointerLevel = getPointerLevel(objPN->getValue());
  if (pointerLevel == 1) {
    assert(not isa<CallInst>(objPN->getValue()) || memObj->isHeap());
    objPNs.emplace(objPN);
  } else if (pointerLevel > 1) {
    // SVF models ConstantObj as special ObjPN#1, so there is no individual
    // ObjPN for string constant etc..
    for (SVF::NodeID deepObjNodeID : ander->getPts(objPN->getId())) {
      SVF::ObjVar *deepObjPN = cast<SVF::ObjVar>(pag->getGNode(deepObjNodeID));
      if (isa<SVF::DummyObjVar>(deepObjPN) ||
          deepObjPN->getMemObj()->isFunction())
        continue;
      assert(getPointerLevel(deepObjPN->getValue()) < pointerLevel);
      objPNs.merge(getNonPtrObjPNs(deepObjPN));
    }
  } else {
    abort();
  }
  return objPNs;
}

void SensitiveLeakSanitizer::pushSensitiveObj(Value *annotatedPtr) {
  std::unordered_set<SVF::ObjVar *> objSet = getNonPtrObjPNs(annotatedPtr);
  assert(objSet.size() <= 1);
  for (auto obj : objSet) {
    addAndPoisonSensitiveObj(obj);
  }
}

bool SensitiveLeakSanitizer::isAnnotationIntrinsic(CallInst *CI) {
  assert(CI);
  auto calleeName = getDirectCalleeName(CI);
  return calleeName.contains("llvm") && calleeName.contains("annotation");
}

bool SensitiveLeakSanitizer::ContainWord(StringRef str,
                                         const std::string word) {
  std::string lowercaseWord = word;
  std::for_each(lowercaseWord.begin(), lowercaseWord.end(),
                [](char &c) { c = std::tolower(c); });
  // underscore naming (lower case)
  if (str.contains(lowercaseWord))
    return true;
  std::string uppercaseWord = lowercaseWord;
  std::for_each(uppercaseWord.begin(), uppercaseWord.end(),
                [](char &c) { c = std::toupper(c); });
  // underscore naming (upper case)
  if (str.contains(uppercaseWord))
    return true;
  std::string capitalWord = lowercaseWord;
  capitalWord[0] = std::toupper(capitalWord[0]);
  // Camel case naming
  return str.contains(capitalWord);
}

bool SensitiveLeakSanitizer::ContainWordExactly(StringRef str,
                                                const std::string word) {
  if (word == "")
    return true;
  else if (str == "")
    return false;
  // filter out non-alphanumeric word
  std::regex nonAlphanumeric("[^0-9a-zA-Z]");
  if (std::regex_search(word, nonAlphanumeric)) {
    errs() << "[ERROR] Word contain non-alphanumeric\n";
    abort();
  }
  // filter out non-word str
  std::regex word_regex("^\\S+$");
  if (not std::regex_match(str.str(), word_regex)) {
    errs() << "[ERROR] str isn't a valid word\n";
    abort();
  }

  // get lowercase word
  std::string lowercaseWord = word;
  std::for_each(lowercaseWord.begin(), lowercaseWord.end(),
                [](char &c) { c = std::tolower(c); });
  std::regex wordRegex("([^a-zA-Z]|^)" + lowercaseWord + "([^a-zA-Z]|$)",
                       std::regex_constants::icase);
  if (std::regex_search(str.str(), wordRegex))
    return true;

  // get capitalized word
  std::string capitalWord = lowercaseWord;
  capitalWord[0] = std::toupper(capitalWord[0]);
  // Camel case naming
  std::regex capitalWordRegex("(^" + lowercaseWord + "|" + capitalWord +
                              ")([^a-z]|$)");
  return std::regex_search(str.str(), capitalWordRegex);
}

bool SensitiveLeakSanitizer::isEncryptionFunction(Function *F) {
  StringRef funcName = F->getName();
  return ((ContainWord(funcName, "encrypt") &&
           !ContainWord(funcName, "decrypt") &&
           !ContainWord(funcName, "encrypted")) ||
          (ContainWord(funcName, "seal") && !ContainWord(funcName, "unseal") &&
           !ContainWord(funcName, "sealed")))
             ? true
             : false;
}

void SensitiveLeakSanitizer::RTPoisonSensitiveGV() {
  size_t N = globalsToBePolluted.size();
  if (N > 0) {
    PoisonSensitiveGlobalModuleCtor =
        createSanitizerCtor(*M, "PoisonSensitiveGlobalModuleCtor");
    IRBuilder<> IRB(
        PoisonSensitiveGlobalModuleCtor->getEntryBlock().getTerminator());

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

DICompositeType *
SensitiveLeakSanitizer::getDICompositeType(StructType *structTy) {
  if (structTy == nullptr)
    return nullptr;
  std::regex structPrefix("^struct\\.(.*)");
  std::smatch match;
  std::string structName = structTy->getName().str();
  if (std::regex_search(structName, match, structPrefix)) {
    auto structName = match[1].str();
    auto result = DICompositeTypeMap.find(structName);
    if (result != DICompositeTypeMap.end()) {
      return result->second;
    }
  }
  return nullptr;
}

StructType *
SensitiveLeakSanitizer::getStructTypeOfHeapObj(SVF::ObjVar *heapObjPN) {
  assert(heapObjPN->getMemObj()->isHeap());
  CallInst *objCI = cast<CallInst>(const_cast<Value *>(heapObjPN->getValue()));
  assert(getPointerLevel(objCI) == 1);
  StructType *structTy = dyn_cast<StructType>(
      cast<PointerType>(objCI->getType())->getElementType());
  if (!structTy) {
    CastInst *castI = dyn_cast<CastInst>(objCI->getNextNode());
    if (castI && castI->getOperand(0) == objCI) {
      assert(getPointerLevel(castI) == 1);
      structTy = dyn_cast<StructType>(
          cast<PointerType>(castI->getDestTy())->getElementType());
    }
  }
  return structTy;
}

SensitiveLevel SensitiveLeakSanitizer::getSensitiveLevel(StringRef str) {
  if (isSensitive(str))
    return IS_SENSITIVE;
  else if (mayBeSensitive(str))
    return MAY_BE_SENSITIVE;
  else
    return NOT_SENSITIVE;
}

bool SensitiveLeakSanitizer::isSensitive(StringRef str) {
  return (std::find_if(plaintextKeywords.begin(), plaintextKeywords.end(),
                       [&](std::string keyword) {
                         return ContainWord(str, keyword);
                       }) != plaintextKeywords.end() ||
          std::find_if(exactSecretKeywords.begin(), exactSecretKeywords.end(),
                       [&](std::string keyword) {
                         return ContainWordExactly(str, keyword);
                       }) != exactSecretKeywords.end()) &&
         not(std::find_if(ciphertextKeywords.begin(), ciphertextKeywords.end(),
                          [&](std::string keyword) {
                            return ContainWord(str, keyword);
                          }) != ciphertextKeywords.end() ||
             std::find_if(exactCiphertextKeywords.begin(),
                          exactCiphertextKeywords.end(),
                          [&](std::string keyword) {
                            return ContainWordExactly(str, keyword);
                          }) != exactCiphertextKeywords.end());
}

bool SensitiveLeakSanitizer::mayBeSensitive(StringRef str) {
  return std::find_if(inputKeywords.begin(), inputKeywords.end(),
                      [&](std::string keyword) {
                        return ContainWord(str, keyword);
                      }) != inputKeywords.end() ||
         std::find_if(exactInputKeywords.begin(), exactInputKeywords.end(),
                      [&](std::string keyword) {
                        return ContainWordExactly(str, keyword);
                      }) != exactInputKeywords.end();
}

bool SensitiveLeakSanitizer::getSubfieldSensitiveIndicator(
    DIType *ty, std::pair<bool *, size_t> *sensitiveIndicator, size_t offset) {
  assert(ty->getTag() == dwarf::DW_TAG_member);
  auto memOffset = ty->getOffsetInBits();
  // strip typedef DIDerivedType
  while (ty && isa<DIDerivedType>(ty) &&
         cast<DIDerivedType>(ty)->getTag() == dwarf::DW_TAG_typedef) {
    ty = cast<DIDerivedType>(ty)->getBaseType();
  }

  // is a structure type
  if (ty && isa<DICompositeType>(ty) &&
      cast<DICompositeType>(ty)->getTag() == dwarf::DW_TAG_structure_type) {
    assert(memOffset == ty->getOffsetInBits());
    return getSensitiveIndicator(cast<DICompositeType>(ty), sensitiveIndicator,
                                 memOffset + offset);
  }
  return false;
}

bool SensitiveLeakSanitizer::getSensitiveIndicator(
    DICompositeType *compositeTy, std::pair<bool *, size_t> *sensitiveIndicator,
    size_t offset) {
  // must be a structure
  if (compositeTy->getTag() != dwarf::DW_TAG_structure_type)
    return false;

  bool hasPoisonedSensitive = false;
  for (auto ele : compositeTy->getElements()) {
    auto *eleTy = cast<DIType>(ele);
    if (isSensitive(eleTy->getName())) {
      if (getSubfieldSensitiveIndicator(eleTy, sensitiveIndicator, offset) ==
          false) {
        // mark the whole as sensitive
        size_t startBit = eleTy->getOffsetInBits() + offset;
        size_t endBit = startBit + eleTy->getSizeInBits() - 1;
        assert(endBit >= startBit);
        size_t startShadowByte = startBit / (8 * (1UL << Mapping.Scale));
        size_t endShadowByte = endBit / (8 * (1UL << Mapping.Scale));
        assert(endShadowByte <= sensitiveIndicator->second);
        memset(sensitiveIndicator->first + startShadowByte, 1,
               endShadowByte - startShadowByte + 1);
      }
      hasPoisonedSensitive = true;
    } else {
      hasPoisonedSensitive |=
          getSubfieldSensitiveIndicator(eleTy, sensitiveIndicator, offset);
    }
  }
  return hasPoisonedSensitive;
}

StringRef SensitiveLeakSanitizer::getObjMeaningfulName(SVF::ObjVar *objPN) {
  StringRef objName = objPN->getValue()->getName();
  if (objPN->getMemObj()->isHeap()) {
    auto obj = const_cast<Value *>(objPN->getValue());
    assert(isa<CallInst>(obj));
    for (auto user : getNonCastUsers(obj)) {
      if (auto StoreI = dyn_cast<StoreInst>(user)) {
        if (stripCast(StoreI->getValueOperand()) == obj) {
          objName = StoreI->getPointerOperand()->getName();
          if (objName != "")
            break;
        }
      }
    }
  }
  return objName;
}

void SensitiveLeakSanitizer::collectAndPoisonSensitiveObj() {
  auto CallInstVec = SGXSanInstVisitor::visitModule(*M).CallInstVec;
  for (auto CI : CallInstVec) {
    for (auto callee : getDirectAndIndirectCalledFunction(CI)) {
      if (isEncryptionFunction(callee)) {
        std::vector<unsigned int> argNoVec;
        if (callee->isDeclaration()) {
          for (unsigned int i = 0; i < CI->getNumArgOperands(); i++) {
            argNoVec.push_back(i);
          }
        } else {
          for (Argument &arg : callee->args()) {
            if (arg.getName() != "" &&
                getSensitiveLevel(arg.getName()) != NOT_SENSITIVE) {
              argNoVec.push_back(arg.getArgNo());
            }
          }
        }
        for (auto argNo : argNoVec) {
          for (auto objPN : getNonPtrObjPNs(CI->getArgOperand(argNo))) {
            auto objName = getObjMeaningfulName(objPN);
            if (objName != "") {
              auto sensitiveLevel = getSensitiveLevel(objName);
              if (sensitiveLevel == IS_SENSITIVE ||
                  sensitiveLevel == MAY_BE_SENSITIVE) {
                std::pair<bool *, size_t> sensitiveIndicator{nullptr, 0};
                if (sensitiveLevel == MAY_BE_SENSITIVE) {
                  if (objPN->getMemObj()->isHeap()) {
                    auto compositeTy =
                        getDICompositeType(getStructTypeOfHeapObj(objPN));
                    if (compositeTy && compositeTy->getSizeInBits() != 0 &&
                        compositeTy->getTag() == dwarf::DW_TAG_structure_type) {
                      sensitiveIndicator.second =
                          RoundUpUDiv(compositeTy->getSizeInBits(),
                                      8 * (1UL << Mapping.Scale));
                      sensitiveIndicator.first = (bool *)calloc(
                          sensitiveIndicator.second, sizeof(bool));
                      if (getSensitiveIndicator(
                              compositeTy, &sensitiveIndicator, 0) == false) {
                        sensitiveIndicator.second = 0;
                      }
                    }
                  }
                }
                addAndPoisonSensitiveObj(objPN, sensitiveIndicator.second
                                                    ? &sensitiveIndicator
                                                    : nullptr);
                free(sensitiveIndicator.first);
              }
            }
          }
        }
      }
    }
  }

  if (GlobalVariable *globalAnnotation =
          M->getGlobalVariable("llvm.global.annotations")) {
    for (Value *GAOp : globalAnnotation->operands()) {
      for (Value *CAOp : cast<ConstantArray>(GAOp)->operands()) {
        ConstantStruct *CS = cast<ConstantStruct>(CAOp);
        std::string annotation = extractAnnotation(CS->getOperand(1));
        if (annotation == "SGXSAN_SENSITIVE") {
          Value *annotatedVar = CS->getOperand(0);
          ConstantExpr *CE = dyn_cast<ConstantExpr>(annotatedVar);
          while (CE && CE->getOpcode() == Instruction::BitCast) {
            annotatedVar = CE->getOperand(0);
            CE = dyn_cast<ConstantExpr>(annotatedVar);
          }
          pushSensitiveObj(annotatedVar);
        }
      }
    }
  }
  RTPoisonSensitiveGV();

  for (auto CI : CallInstVec) {
    if (isAnnotationIntrinsic(CI)) {
      Value *annotatedPtr = CI->getArgOperand(0),
            *annotateStr = CI->getArgOperand(1);
      assert(isa<PointerType>(annotatedPtr->getType()));
      std::string annotation = extractAnnotation(annotateStr);
      if (annotation == "SGXSAN_SENSITIVE") {
        pushSensitiveObj(annotatedPtr);
      }
    }
  }
}

void dump(ordered_json js) { dbgs() << js.dump(4) << "\n"; }

void SensitiveLeakSanitizer::updateSVFExtAPI() {
  // register heap allocator wrappers to SVF ExtAPI.json
  ExtAPIJsonFile = std::string(SVF_PROJECT_PATH) + "/" + EXTAPI_JSON_PATH;
  auto targetPath = fs::path(ExtAPIJsonFile),
       origPath = fs::path(ExtAPIJsonFile + ".orig");
  if (fs::exists(origPath)) {
    fs::remove(targetPath);
    fs::copy(ExtAPIJsonFile + ".orig", ExtAPIJsonFile);
  } else {
    fs::copy(ExtAPIJsonFile, ExtAPIJsonFile + ".orig");
  }
  std::ifstream ifs(ExtAPIJsonFile);
  if (not ifs.is_open())
    abort();
  std::stringstream buffer;
  buffer << ifs.rdbuf();
  auto ExtAPIJson = ordered_json::parse(buffer.str());
  for (auto name : heapAllocatorWrapperNames) {
    ordered_json::json_pointer ptr("/" + name);
    ExtAPIJson[ptr / "type"] = "EFT_ALLOC";
    ExtAPIJson[ptr / "overwrite_app_function"] = 1;
  }
  std::ofstream ofs(ExtAPIJsonFile, ofs.trunc);
  ofs << ExtAPIJson.dump(4);
}

void SensitiveLeakSanitizer::initSVF() {
  collectHeapAllocators();
  updateSVFExtAPI();
  svfModule = SVF::LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(*M);
  svfModule->buildSymbolTableInfo();
  SVF::SVFIRBuilder builder;

  pag = builder.build(svfModule);

  ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);
  callgraph = ander->getPTACallGraph();
  objSym = &SVF::SymbolTableInfo::SymbolInfo()->objSyms();
}

void SensitiveLeakSanitizer::initializeCallbacks() {
  IRBuilder<> IRB(*C);

  // Declare functions of ArgShadow
  PoisonArg = M->getOrInsertFunction("PoisonArg", IRB.getVoidTy(),
                                     IRB.getInt8PtrTy(), IRB.getInt32Ty());
  ArgIsPoisoned = M->getOrInsertFunction("ArgIsPoisoned", IRB.getInt1Ty(),
                                         IRB.getInt8PtrTy(), IRB.getInt32Ty());
  PushArgShadowStack = M->getOrInsertFunction(
      "PushArgShadowStack", IRB.getVoidTy(), IRB.getInt8PtrTy());
  PopArgShadowStack = M->getOrInsertFunction(
      "PopArgShadowStack", IRB.getVoidTy(), IRB.getInt8PtrTy());

  // Declare check
  IsWithinEnclave = M->getOrInsertFunction(
      "sgx_is_within_enclave", IRB.getInt32Ty(), IRB.getInt8PtrTy(), IntptrTy);
  RegionIsInEnclaveAndPoisoned =
      M->getOrInsertFunction("RegionIsInEnclaveAndPoisoned", IRB.getInt1Ty(),
                             IntptrTy, IntptrTy, IRB.getInt8Ty());

  // Print util
  SGXSanLog = M->getOrInsertFunction("sgxsan_log", Type::getVoidTy(*C),
                                     Type::getInt32Ty(*C), Type::getInt1Ty(*C),
                                     Type::getInt8PtrTy(*C));
  PrintPtr = M->getOrInsertFunction("PrintPtr", Type::getVoidTy(*C),
                                    Type::getInt8PtrTy(*C),
                                    Type::getInt8PtrTy(*C), IntptrTy);
  PrintArg = M->getOrInsertFunction(
      "PrintArg", Type::getVoidTy(*C), Type::getInt8PtrTy(*C),
      Type::getInt8PtrTy(*C), Type::getInt32Ty(*C));
  MallocUsableSize = M->getOrInsertFunction(
      "malloc_usable_size", IRB.getInt64Ty(), IRB.getInt8PtrTy());

  // Declare functions for poisoning sensitive data
  PoisonSensitiveGlobal = M->getOrInsertFunction(
      "PoisonSensitiveGlobal", IRB.getVoidTy(), IntptrTy, IntptrTy);
  ShallowPoisonShadow =
      M->getOrInsertFunction("ShallowPoisonShadow", IRB.getVoidTy(), IntptrTy,
                             IntptrTy, IRB.getInt8Ty(), IRB.getInt1Ty());
  MoveShallowShadow =
      M->getOrInsertFunction("MoveShallowShadow", IRB.getVoidTy(), IntptrTy,
                             IntptrTy, IntptrTy, IntptrTy);
  ReportSensitiveDataLeak = M->getOrInsertFunction(
      "ReportSensitiveDataLeak", IRB.getVoidTy(), IRB.getInt32Ty(), IntptrTy,
      IntptrTy, IntptrTy, IntptrTy);

  initSVF();
  analyseModuleMetadata();
}

void SensitiveLeakSanitizer::collectHeapAllocatorGlobalPtrs() {
  for (GlobalVariable &GV : M->globals()) {
    if (GV.hasInitializer()) {
      Function *init = dyn_cast<Function>(GV.getInitializer());
      if (init && heapAllocators.count(init)) {
        heapAllocatorGlobalPtrs.insert(&GV);
      }
    }
  }
}

// A function is a heap allocator wrapper if it allocates memory using malloc
// etc., and returns the same pointer.
bool SensitiveLeakSanitizer::isHeapAllocatorWrapper(Function &F) {
  // A heap allocator wrapper can have multiple allocator calls on different
  // conditional branches as well as multiple return instructions
  std::vector<CallInst *> heapPtrs;
  if (!F.getFunctionType()->getReturnType()->isPointerTy())
    return false;

  auto &visitInfo = SGXSanInstVisitor::visitFunction(F);
  auto CallInstVec = visitInfo.CallInstVec;
  auto RetInstVec = visitInfo.ReturnInstVec;

  for (auto CallI : CallInstVec) {
    Function *calleeFunc = getCalledFunctionStripPointerCast(CallI);
    Value *calleeValue = CallI->getCalledOperand();
    // Direct call
    if (calleeFunc && heapAllocators.count(calleeFunc)) {
      heapPtrs.push_back(CallI);
    }
    // Indirect call, then find if the function pointer is a global pointer that
    // point to heap allocator
    else if (calleeFunc == nullptr) {
      if (LoadInst *LoadI = dyn_cast<LoadInst>(calleeValue)) {
        // TODO: deal with uninitialized heapAllocatorGlobalPtr
        GlobalVariable *GV =
            dyn_cast<GlobalVariable>(LoadI->getPointerOperand());
        if (GV && heapAllocatorGlobalPtrs.count(GV)) {
          heapPtrs.push_back(CallI);
        }
      }
    }
  }

  // If this function doesn't call heap allocator
  if (heapPtrs.size() == 0) {
    return false;
  }

  // For all return instructions, check whether returned values are in heapPtrs
  for (ReturnInst *RetI : RetInstVec) {
    if (std::find_if(heapPtrs.begin(), heapPtrs.end(), [&](CallInst *heapPtr) {
          return AAResult->query(
              MemoryLocation(RetI->getOperand(0), MemoryLocation::UnknownSize),
              MemoryLocation(heapPtr, MemoryLocation::UnknownSize));
        }) == heapPtrs.end()) {
      return false;
    }
  }
  return true;
}

void SensitiveLeakSanitizer::collectHeapAllocators() {

  for (auto funcName : heapAllocatorBaseNames) {
    if (Function *func = M->getFunction(funcName)) {
      heapAllocators.insert(func);
    }
  }

  for (int num = 0; num < ClHeapAllocatorsMaxCollectionTimes; num++) {
    // Handle global function pointers
    collectHeapAllocatorGlobalPtrs();
    for (Function &F : *M) {
      if (!F.isDeclaration() && isHeapAllocatorWrapper(F)) {
        heapAllocators.insert(&F);
      }
    }
  }
  for (auto heapAllocator : heapAllocators) {
    auto funcName = heapAllocator->getName().str();
    dbgs() << "[HeapAllocator] " << funcName << "\n";
    heapAllocatorNames.insert(funcName);
    if (heapAllocatorBaseNames.count(funcName) == 0) {
      heapAllocatorWrapperNames.insert(funcName);
    }
  }
}

void SensitiveLeakSanitizer::analyseDIType(DIType *type) {
  if (type == nullptr || processedDITypes.count(type) == 1)
    return;
  processedDITypes.insert(type);
  if (auto compositeTy = dyn_cast<DICompositeType>(type)) {
    auto tyName = compositeTy->getName();
    if (tyName != "") {
      // dbgs() << "[Struct Name]" << tyName << "\n";
      DICompositeTypeMap[tyName.str()] = compositeTy;
    }
    auto tyIdName = compositeTy->getIdentifier();
    if (tyIdName != "") {
      // dbgs() << "[Struct Identifier]" << tyName << "\n";
      DICompositeTypeMap[tyIdName.str()] = compositeTy;
    }
    analyseDIType(compositeTy->getBaseType());
    for (auto ele : compositeTy->getElements()) {
      if (ele == nullptr)
        continue;
      if (auto eleTy = dyn_cast<DIType>(ele))
        analyseDIType(eleTy);
    }
  } else if (auto derivedTy = dyn_cast<DIDerivedType>(type)) {
    analyseDIType(derivedTy->getBaseType());
  } else if (auto subroutineTy = dyn_cast<DISubroutineType>(type)) {
    for (auto paramTy : subroutineTy->getTypeArray())
      analyseDIType(paramTy);
  }
}

void SensitiveLeakSanitizer::analyseModuleMetadata() {
  if (auto dbg_cu = M->getNamedMetadata("llvm.dbg.cu")) {
    for (auto CU : dbg_cu->operands()) {
      for (auto retainedType : cast<DICompileUnit>(CU)->getRetainedTypes()) {
        if (auto type = dyn_cast<DIType>(retainedType)) {
          analyseDIType(type);
        } else {
          abort();
        }
      }
    }
  }
}

SensitiveLeakSanitizer::SensitiveLeakSanitizer(Module &M) {
  C = &(M.getContext());
  int LongSize = M.getDataLayout().getPointerSizeInBits();
  IntptrTy = Type::getIntNTy(*C, LongSize);
  Triple TargetTriple = Triple(M.getTargetTriple());
  Mapping = ASanGetShadowMapping(TargetTriple, LongSize, false);
}

SensitiveLeakSanitizer::~SensitiveLeakSanitizer() {
  // Restore ExtAPI.json
  fs::rename(ExtAPIJsonFile + ".orig", ExtAPIJsonFile);
}

std::unordered_set<SVF::ValVar *>
SensitiveLeakSanitizer::getRevPtValPNs(SVF::ObjVar *objPN) {
  std::unordered_set<SVF::ValVar *> revPtValPNs;
  for (SVF::NodeID revPtValPNID : ander->getRevPts(objPN->getId())) {
    if (not pag->hasGNode(revPtValPNID))
      continue;
    if (auto revPtValPN = dyn_cast<SVF::ValVar>(pag->getGNode(revPtValPNID))) {
      if (isa<SVF::DummyValVar>(revPtValPN))
        continue;
      if (getPointerLevel(revPtValPN->getValue()) ==
          getPointerLevel(objPN->getValue())) {
        revPtValPNs.emplace(revPtValPN);
      }
    }
  }
  return revPtValPNs;
}

int SensitiveLeakSanitizer::getCallInstOperandPosition(CallInst *CI,
                                                       Value *operand,
                                                       bool rawOperand) {
  for (unsigned int i = 0; i < CI->getNumOperands(); i++) {
    if (rawOperand ? (CI->getOperand(i) == operand)
                   : (stripCast(CI->getOperand(i)) == operand)) {
      return i;
    }
  }
  return -1;
}

SmallVector<Function *>
SensitiveLeakSanitizer::getDirectAndIndirectCalledFunction(CallInst *CI) {
  SmallVector<Function *> calleeVec;
  Function *callee = getCalledFunctionStripPointerCast(CI);
  if (callee == nullptr) {
    // it's an indirect call
    for (auto indCall : callgraph->getIndCallMap()) {
      if (indCall.first->getCallSite() == CI) {
        for (auto svfCallee : indCall.second) {
          calleeVec.push_back(svfCallee->getLLVMFun());
        }
      }
    }
  } else {
    // it's a direct call
    calleeVec.push_back(callee);
  }
  return calleeVec;
}

Instruction *SensitiveLeakSanitizer::findInstByName(Function *F,
                                                    std::string InstName) {
  for (auto &BB : *F) {
    for (auto &I : BB) {
      if (I.getName().str() == InstName) {
        return &I;
      }
    }
  }

  return nullptr;
}

void SensitiveLeakSanitizer::setNoSanitizeMetadata(Instruction *I) {
  unsigned int MDKindID = I->getModule()->getMDKindID("nosanitize");
  MDNode *node = MDNode::get(*C, None);
  I->setMetadata(MDKindID, node);
}

// check directly with SGXSan shadow map
Value *SensitiveLeakSanitizer::isPtrPoisoned(Instruction *insertPoint,
                                             Value *ptr, Value *size) {
  IRBuilder<> IRB(insertPoint);
  return IRB.CreateCall(
      RegionIsInEnclaveAndPoisoned,
      {IRB.CreatePtrToInt(ptr, IntptrTy),
       size ? IRB.CreateIntCast(size, IntptrTy, false)
            : ConstantInt::get(IntptrTy,
                               M->getDataLayout().getTypeAllocSize(
                                   ptr->getType()->getPointerElementType())),
       IRB.getInt8(kSGXSanSensitiveObjData)});
}

void SensitiveLeakSanitizer::pushAndPopArgShadowStack(CallInst *CI) {
  if (poisonedCI.count(CI) != 0)
    return;
  // instrument push_thread_func_arg_shadow_stack
  IRBuilder<> IRB(CI);
  Value *calleeAddr =
      IRB.CreatePointerCast(CI->getCalledOperand(), IRB.getInt8PtrTy());
  IRB.CreateCall(PushArgShadowStack, calleeAddr);

  // instrument pop_thread_func_arg_shadow_stack
  IRB.SetInsertPoint(CI->getNextNode());
  IRB.CreateCall(PopArgShadowStack, calleeAddr);

  // record this CI has been instrumented with
  // push/pop_thread_func_arg_shadow_stack
  poisonedCI.emplace(CI, std::unordered_set<int>{});
}

Value *SensitiveLeakSanitizer::instrumentPoisonCheck(Value *val) {
  if (poisonCheckedValues.count(val) != 0) {
    return poisonCheckedValues[val];
  }
  // never instrumented to check whether value is poisoned
  Value *isPoisoned = nullptr;
  if (LoadInst *LI = dyn_cast<LoadInst>(val)) {
    // Check whether loaded memory is poisoned
    isPoisoned = isPtrPoisoned(LI, LI->getPointerOperand());
  } else if (Argument *arg = dyn_cast<Argument>(val)) {
    // Check argument
    IRBuilder<> IRB(&arg->getParent()->front().front());
    isPoisoned = IRB.CreateCall(
        ArgIsPoisoned,
        {IRB.CreatePointerCast(arg->getParent(), IRB.getInt8PtrTy()),
         IRB.getInt32(arg->getArgNo())});
  } else if (CallInst *CI = dyn_cast<CallInst>(val)) {
    // Check return value
    pushAndPopArgShadowStack(CI);
    IRBuilder<> IRB(CI->getNextNode());
    isPoisoned = IRB.CreateCall(
        ArgIsPoisoned,
        {IRB.CreatePointerCast(CI->getCalledOperand(), IRB.getInt8PtrTy()),
         IRB.getInt32(-1)});
  } else {
    abort();
  }
  // record this source value has been checked whether is poisoned
  poisonCheckedValues[val] = isPoisoned;
  return isPoisoned;
}

void SensitiveLeakSanitizer::RTPrintSrc(IRBuilder<> &IRB, Value *src) {
  SensitiveDataType dataType;
  Value *info1, *info2;
  getSensitiveDataInfo(IRB, src, dataType, info1, info2);
  Constant *srcMsgStr = IRB.CreateGlobalStringPtr("\n" + toString(src));
  if (dataType == LoadedData) {
    IRB.CreateCall(PrintPtr, {srcMsgStr, info1, info2});
  } else if (dataType == ArgData or dataType == ReturnedData) {
    IRB.CreateCall(PrintArg, {srcMsgStr, info1, info2});
  } else {
    abort();
  }
}

void SensitiveLeakSanitizer::PoisonCIOperand(Value *src, Value *isPoisoned,
                                             CallInst *CI, int opPos) {
  pushAndPopArgShadowStack(CI);

  // instrument to poison argument shadow
  if (poisonedCI[CI].count(opPos) != 0)
    return;

  propagateCnt++;
  Instruction *srcIsPoisonedTerm =
      SplitBlockAndInsertIfThen(isPoisoned, CI, false);
  IRBuilder<> IRB(srcIsPoisonedTerm);
  auto calleePtr =
      IRB.CreatePointerCast(CI->getCalledOperand(), IRB.getInt8PtrTy());
#ifdef DUMP_VALUE_FLOW
  RTPrintSrc(IRB, src);
  IRB.CreateCall(PrintArg,
                 {IRB.CreateGlobalStringPtr("-[" + std::to_string(opPos) +
                                            "th Arg]->\n" + toString(CI)),
                  calleePtr, IRB.getInt32(opPos)});
#endif
  IRB.CreateCall(PoisonArg, {calleePtr, IRB.getInt32(opPos)});
  // record this argument's shadow has been poisoned
  poisonedCI[CI].emplace(opPos);
}

uint64_t SensitiveLeakSanitizer::RoundUpUDiv(uint64_t dividend,
                                             uint64_t divisor) {
  return (dividend + divisor - 1) / divisor;
}

Value *SensitiveLeakSanitizer::CheckIsPtrInEnclave(Value *ptr, Value *size,
                                                   Instruction *insertPt,
                                                   const DebugLoc *dbgLoc) {
  IRBuilder<> IRB(insertPt);
  CallInst *IsWithinEnclaveCall = IRB.CreateCall(
      IsWithinEnclave, {IRB.CreatePointerCast(ptr, IRB.getInt8PtrTy()), size});
  IsWithinEnclaveCall->setDebugLoc(*dbgLoc);
  return IRB.CreateICmpEQ(IsWithinEnclaveCall, IRB.getInt32(1));
}

void SensitiveLeakSanitizer::PoisonSI(Value *src, Value *isPoisoned,
                                      StoreInst *SI) {
  if (poisonedInst.count(SI) != 0)
    return;

  propagateCnt++;
  Instruction *srcIsPoisonedTerm =
      SplitBlockAndInsertIfThen(isPoisoned, SI, false);
  IRBuilder<> IRB(srcIsPoisonedTerm);
  Value *dstPtr = SI->getPointerOperand();
  assert(not isa<Function>(dstPtr));
  auto _dstPtrEleSize = M->getDataLayout().getTypeAllocSize(
      dstPtr->getType()->getPointerElementType());
  assert(_dstPtrEleSize > 0);
  Value *dstPtrEleSize = ConstantInt::get(IntptrTy, _dstPtrEleSize);

  auto isDstInEnclave = CheckIsPtrInEnclave(
      dstPtr, dstPtrEleSize, srcIsPoisonedTerm, &SI->getDebugLoc());

  Instruction *dstIsInEnclaveTerm, *dstIsOutEnclaveTerm;
  SplitBlockAndInsertIfThenElse(isDstInEnclave, srcIsPoisonedTerm,
                                &dstIsInEnclaveTerm, &dstIsOutEnclaveTerm);

  IRB.SetInsertPoint(dstIsOutEnclaveTerm);
  SensitiveDataType srcDataType;
  Value *srcInfo1, *srcInfo2;
  getSensitiveDataInfo(IRB, src, srcDataType, srcInfo1, srcInfo2);
  IRB.CreateCall(ReportSensitiveDataLeak,
                 {IRB.getInt32(srcDataType), srcInfo1, srcInfo2,
                  IRB.CreatePtrToInt(dstPtr, IntptrTy), dstPtrEleSize});

  IRB.SetInsertPoint(dstIsInEnclaveTerm);
#ifdef DUMP_VALUE_FLOW
  RTPrintSrc(IRB, src);
  IRB.CreateCall(PrintPtr,
                 {IRB.CreateGlobalStringPtr("-[Store]->\n" + toString(SI)),
                  IRB.CreatePointerCast(dstPtr, IRB.getInt8PtrTy()),
                  dstPtrEleSize});
#endif
  IRB.CreateCall(ShallowPoisonShadow,
                 {IRB.CreatePtrToInt(dstPtr, IntptrTy), dstPtrEleSize,
                  IRB.getInt8(kSGXSanSensitiveObjData), IRB.getInt1(true)});
  ShallowUnpoisonStackObj(dstPtr);
  poisonedInst.emplace(SI);
}

void SensitiveLeakSanitizer::PoisonRetShadow(Value *src, Value *isPoisoned,
                                             ReturnInst *calleeRI) {
  if (poisonedInst.count(calleeRI) != 0)
    return;
  propagateCnt++;
  Instruction *srcIsPoisonedTerm =
      SplitBlockAndInsertIfThen(isPoisoned, calleeRI, false);
  IRBuilder<> IRB(srcIsPoisonedTerm);
  Value *calleePtr =
      IRB.CreatePointerCast(calleeRI->getFunction(), IRB.getInt8PtrTy());
#ifdef DUMP_VALUE_FLOW
  RTPrintSrc(IRB, src);
  IRB.CreateCall(PrintArg, {IRB.CreateGlobalStringPtr("-[Return]->\n" +
                                                      toString(calleeRI)),
                            calleePtr, IRB.getInt32(-1)});
#endif
  IRB.CreateCall(PoisonArg, {calleePtr, IRB.getInt32(-1)});
  poisonedInst.emplace(calleeRI);
}

void SensitiveLeakSanitizer::addPtObj2WorkList(Value *ptr) {
  assert(ptr->getType()->isPointerTy() && getPointerLevel(ptr) == 1 &&
         not isa<Function>(ptr));
  for (auto objPN : getNonPtrObjPNs(ptr)) {
    if (ProcessedList.count(objPN) == 0)
      WorkList.emplace(objPN);
  }
}

void SensitiveLeakSanitizer::ShallowUnpoisonStackObj(SVF::ObjVar *objPN) {
  assert(objPN);
  if (objPN->hasValue()) {
    AllocaInst *AI =
        dyn_cast<AllocaInst>(const_cast<Value *>(objPN->getValue()));
    // stack object must be a AllocInst
    if (AI && shallowUnpoisonedStackObjs.count(AI) == 0) {
      for (ReturnInst *RI :
           SGXSanInstVisitor::visitFunction(*(AI->getFunction()))
               .ReturnInstVec) {
        IRBuilder<> IRB(RI);
        assert(AI->getAllocatedType()->isSized() && !AI->isSwiftError());
        auto _objSize = getAllocaSizeInBytes(*AI);
        assert(_objSize > 0);
        IRB.CreateCall(
            ShallowPoisonShadow,
            {IRB.CreatePtrToInt(AI, IRB.getInt64Ty()), IRB.getInt64(_objSize),
             IRB.getInt8(kSGXSanSensitiveObjData), IRB.getInt1(false)});
      }
      shallowUnpoisonedStackObjs.emplace(AI);
    }
  }
}

void SensitiveLeakSanitizer::ShallowUnpoisonStackObj(Value *value) {
  assert(value);
  if (isa<Function>(value))
    return;
  for (auto objPN : getTargetObj(value)) {
    // inter-function situation may have multi point-tos
    ShallowUnpoisonStackObj(objPN);
  }
}

void SensitiveLeakSanitizer::propagateShadowInMemTransfer(
    CallInst *CI, Instruction *insertPoint, Value *dstPtr, Value *srcPtr,
    Value *dstSize, Value *copyCnt) {
  assert(CI != nullptr && not isa<Function>(dstPtr));
  if (processedMemTransferInst.count(CI) != 0)
    return;

  // current memory transfer instruction has never been instrumented
  propagateCnt++;
  IRBuilder<> IRB(insertPoint);
  copyCnt = IRB.CreateIntCast(copyCnt, IntptrTy, false);
  dstSize = IRB.CreateIntCast(dstSize, IntptrTy, false);
  // we have to avoid 0-size in mem transfer call
  auto sizeNot0 =
      IRB.CreateAnd(IRB.CreateICmpNE(dstSize, ConstantInt::get(IntptrTy, 0)),
                    IRB.CreateICmpNE(copyCnt, ConstantInt::get(IntptrTy, 0)));
  Instruction *sizeNot0Term =
      SplitBlockAndInsertIfThen(sizeNot0, insertPoint, false);

  Value *isSrcPoisoned = isPtrPoisoned(sizeNot0Term, srcPtr, copyCnt);
  Instruction *srcIsPoisonedTerm =
      SplitBlockAndInsertIfThen(isSrcPoisoned, sizeNot0Term, false);
  IRB.SetInsertPoint(srcIsPoisonedTerm);
  auto isDstInEnclave = CheckIsPtrInEnclave(dstPtr, dstSize, srcIsPoisonedTerm,
                                            &CI->getDebugLoc());

  Instruction *dstIsInEnclaveTerm =
      SplitBlockAndInsertIfThen(isDstInEnclave, srcIsPoisonedTerm, false);
  IRB.SetInsertPoint(dstIsInEnclaveTerm);
#ifdef DUMP_VALUE_FLOW
  IRB.CreateCall(PrintPtr,
                 {IRB.CreateGlobalStringPtr(toString(srcPtr)),
                  IRB.CreatePointerCast(srcPtr, IRB.getInt8PtrTy()), copyCnt});
  IRB.CreateCall(
      PrintPtr,
      {IRB.CreateGlobalStringPtr("-[Mem Transfer]->\n" + toString(dstPtr)),
       IRB.CreatePointerCast(dstPtr, IRB.getInt8PtrTy()), dstSize});
#endif
  IRB.CreateCall(MoveShallowShadow,
                 {IRB.CreatePtrToInt(dstPtr, IntptrTy),
                  IRB.CreatePtrToInt(srcPtr, IntptrTy), dstSize, copyCnt});

  addPtObj2WorkList(dstPtr);
  ShallowUnpoisonStackObj(dstPtr);
  // record this memory transfer CI has been instrumented
  processedMemTransferInst.emplace(CI);
}

bool SensitiveLeakSanitizer::isSecureVersionMemTransferCI(CallInst *CI) {
  auto calleeName = getDirectCalleeName(CI);
  return calleeName == "memcpy_s" || calleeName == "memmove_s";
}

void SensitiveLeakSanitizer::doVFA(Value *work) {
  for (User *user : work->users()) {
    if (LoadInst *LI = dyn_cast<LoadInst>(user)) {
      propagateShadow(LI);
    } else if (CallInst *CI = dyn_cast<CallInst>(user)) {
      MemTransferInst *MTI = dyn_cast<MemTransferInst>(user);
      if (MTI && MTI->getRawSource() == work) {
        propagateShadowInMemTransfer(MTI, MTI->getNextNode(), MTI->getDest(),
                                     MTI->getSource(), MTI->getOperand(2),
                                     MTI->getOperand(2));
      } else if (isSecureVersionMemTransferCI(CI) &&
                 CI->getOperand(2) == work) {
        propagateShadowInMemTransfer(CI, CI->getNextNode(), CI->getOperand(0),
                                     CI->getOperand(2), CI->getOperand(1),
                                     CI->getOperand(3));
      } else {
        if (getDirectCalleeName(CI).contains("llvm.ptr.annotation")) {
          doVFA(CI);
        }
      }
    }
  }
}

void SensitiveLeakSanitizer::PoisonMemsetDst(Value *src, Value *isSrcPoisoned,
                                             CallInst *MSI, Value *dstPtr,
                                             Value *setSize) {
  if (poisonedInst.count(MSI) != 0)
    return;

  propagateCnt++;
  Instruction *srcIsPoisonedTerm =
      SplitBlockAndInsertIfThen(isSrcPoisoned, MSI, false);
  IRBuilder<> IRB(srcIsPoisonedTerm);
  assert(not isa<Function>(dstPtr));
  auto isDstInElrange = CheckIsPtrInEnclave(dstPtr, setSize, srcIsPoisonedTerm,
                                            &MSI->getDebugLoc());
  Instruction *dstIsInElrangeTerm =
      SplitBlockAndInsertIfThen(isDstInElrange, srcIsPoisonedTerm, false);

  IRB.SetInsertPoint(dstIsInElrangeTerm);
#ifdef DUMP_VALUE_FLOW
  RTPrintSrc(IRB, src);
  IRB.CreateCall(PrintPtr,
                 {IRB.CreateGlobalStringPtr("-[Memset]->\n" + toString(MSI)),
                  IRB.CreatePointerCast(dstPtr, IRB.getInt8PtrTy()), setSize});
#endif
  IRB.CreateCall(ShallowPoisonShadow,
                 {IRB.CreatePtrToInt(dstPtr, IntptrTy), setSize,
                  IRB.getInt8(kSGXSanSensitiveObjData), IRB.getInt1(true)});
  ShallowUnpoisonStackObj(dstPtr);
  poisonedInst.emplace(MSI);
}

void SensitiveLeakSanitizer::propagateShadow(Value *src) {
  // src maybe 'Function Argument'/LoadInst/'Return Value of CallInst'
  for (User *srcUser : getNonCastUsers(src)) {
    if (isa<StoreInst>(srcUser) || isa<CallInst>(srcUser) ||
        isa<ReturnInst>(srcUser)) {
      // there is a value flow, then check whether src is poisoned(at runtime)
      Value *isSrcPoisoned = instrumentPoisonCheck(src);
      if (StoreInst *SI = dyn_cast<StoreInst>(srcUser)) {
        assert(stripCast(SI->getValueOperand()) == src);
        PoisonSI(src, isSrcPoisoned, SI);
        addPtObj2WorkList(SI->getPointerOperand());
      } else if (CallInst *CI = dyn_cast<CallInst>(srcUser)) {
        if (MemSetInst *MSI = dyn_cast<MemSetInst>(CI)) {
          if (stripCast(MSI->getArgOperand(1)) == src) {
            PoisonMemsetDst(src, isSrcPoisoned, MSI, MSI->getArgOperand(0),
                            MSI->getArgOperand(2));
            addPtObj2WorkList(MSI->getArgOperand(0));
          }
        } else if (getDirectCalleeName(CI) == "memset_s") {
          if (stripCast(CI->getArgOperand(2)) == src) {
            IRBuilder<> IRB(CI);
            Value *setSize = IRB.CreateSelect(
                IRB.CreateICmpSLT(CI->getArgOperand(1), CI->getArgOperand(3)),
                CI->getArgOperand(1), CI->getArgOperand(3));
            PoisonMemsetDst(src, isSrcPoisoned, CI, CI->getArgOperand(0),
                            setSize);
            addPtObj2WorkList(CI->getArgOperand(0));
          }
        } else {
          SmallVector<Function *> calleeVec =
              getDirectAndIndirectCalledFunction(CI);
          for (Function *callee : calleeVec) {
            if (callee->isDeclaration() || isEncryptionFunction(callee))
              continue;
            int opPos = getCallInstOperandPosition(CI, src);
            assert(opPos != -1);
            PoisonCIOperand(src, isSrcPoisoned, CI, opPos);
            if (!callee->isVarArg()) {
              auto arg = callee->getArg(opPos);
              if (getPointerLevel(arg) == getPointerLevel(src)) {
                propagateShadow(arg);
              }
            }
          }
        }
      } else if (ReturnInst *RI = dyn_cast<ReturnInst>(srcUser)) {
        assert(stripCast(RI->getOperand(0)) == src);
        Function *callee = RI->getFunction();
        for (auto callInstToCallGraphEdges :
             callgraph->getCallInstToCallGraphEdgesMap()) {
          for (auto callGraphEdge : callInstToCallGraphEdges.second) {
            if (callGraphEdge->getDstNode()->getFunction()->getLLVMFun() ==
                callee) {
              CallInst *callerCI = cast<CallInst>(const_cast<Instruction *>(
                  callInstToCallGraphEdges.first->getCallSite()));
              PoisonRetShadow(src, isSrcPoisoned, RI);
              propagateShadow(callerCI);
            }
          }
        }
      }
    }
  }
}

bool SensitiveLeakSanitizer::runOnModule(Module &M,
                                         CFLSteensAAResult &AAResult) {
  this->M = &M;
  this->AAResult = &AAResult;
  initializeCallbacks();
#ifdef DUMP_VALUE_FLOW
  for (auto &F : M) {
    Instruction *FuncFirstInst = &F.front().front();
    IRBuilder<> IRB(FuncFirstInst);
    IRB.CreateCall(SGXSanLog,
                   {IRB.getInt32(3) /* LOG_LEVEL_DEBUG */, IRB.getInt1(1),
                    IRB.CreateGlobalStringPtr(
                        "[RUN FUNC] " + F.getName() + " " +
                        SVF::SVFUtil::getSourceLoc(FuncFirstInst) + "\n")});
  }
#endif
  collectAndPoisonSensitiveObj();

  for (auto objPN : SensitiveObjs) {
    dump(objPN);
  }
  dbgs() << "[SLSan] Num of collected sensitive objs: "
         << this->SensitiveObjs.size() << "\n";
  WorkList = this->SensitiveObjs;
  propagateCnt = 0;
  while (!WorkList.empty()) {
    // update work status
    SVF::ObjVar *workObjPN = *WorkList.begin();
    WorkList.erase(WorkList.begin());
    ProcessedList.emplace(workObjPN);

#ifdef SHOW_WORK_OBJ_PTS
    dbgs() << "============== Show point-to set ==============\n";
    dump(workObjPN);
    dbgs() << "-----------------------------------------------\n";
#endif
    for (auto revPtValPN : getRevPtValPNs(workObjPN)) {
#ifdef SHOW_WORK_OBJ_PTS
      dump(revPtValPN);
#endif
      doVFA(const_cast<Value *>(revPtValPN->getValue()));
    }
#ifdef SHOW_WORK_OBJ_PTS
    dbgs() << "========= End of showing point-to set ==========\n";
#endif
  }
  dbgs() << "[SLSan] Num of instrumented propagation: " << propagateCnt << "\n";
  return true;
}

void SensitiveLeakSanitizer::dumpPts(SVF::SVFVar *PN) {
  for (SVF::NodeID nodeID : ander->getPts(PN->getId())) {
    assert(pag->hasGNode(nodeID));
    dump(pag->getGNode(nodeID));
  }
}

void SensitiveLeakSanitizer::dumpRevPts(SVF::SVFVar *PN) {
  for (SVF::NodeID nodeID : ander->getRevPts(PN->getId())) {
    if (pag->hasGNode(nodeID)) {
      dump(pag->getGNode(nodeID));
    }
  }
}

std::string SensitiveLeakSanitizer::toString(SVF::SVFVar *PN) {
  std::stringstream ss;
  ss << "[Func] "
     << (PN->hasValue()
             ? ::getParentFuncName(const_cast<Value *>(PN->getValue()))
             : "")
            .str()
     << " [Name] " << PN->getValueName() << " " << PN->toString();
  return ss.str();
}

void SensitiveLeakSanitizer::dump(SVF::NodeID nodeID) {
  assert(pag->hasGNode(nodeID));
  dump(pag->getGNode(nodeID));
}

void SensitiveLeakSanitizer::dump(SVF::SVFVar *PN) {
  dbgs() << toString(PN) << "\n\n";
}

std::string SensitiveLeakSanitizer::toString(Value *val) {
  return ::toString(val) + " " + SVF::SVFUtil::getSourceLoc(val);
}

void SensitiveLeakSanitizer::dump(Value *val) {
  dbgs() << toString(val) << "\n\n";
}