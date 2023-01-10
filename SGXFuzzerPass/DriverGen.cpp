#include "DriverGen.h"
#include "FuzzDataType.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <tuple>
#include <unistd.h>

using namespace llvm;
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

static cl::opt<std::string>
    ClEdlJsonFile("edl-json", cl::init("Enclave.edl.json"),
                  cl::desc("Path of *.edl.json generated by EdlParser.py"),
                  cl::Hidden);

static cl::opt<bool>
    ClEnableFillAtOnce("enable-fill-at-once", cl::init(true),
                       cl::desc("Enable fill parameter data at once for pure "
                                "data that don't contain pointer in subfield"),
                       cl::Hidden);

static cl::opt<std::string>
    ClOCallWrapperPrefix("ocall-wrapper-prefix", cl::init("__ocall_wrapper_"),
                         cl::desc("Prefix of wrapper of OCall, in which we "
                                  "call real OCall and modify return values"),
                         cl::Hidden);

static cl::opt<std::string>
    ClWrapperFuzzECallPrefix("wrapper-fuzz-ecall-prefix", cl::init("fuzz_"),
                             cl::desc("Prefix of wrapper to fuzz ECall"),
                             cl::Hidden);

static cl::opt<size_t> ClMaxRecursionDepthForPointer(
    "max-depth-recursively-prepare-pointer", cl::init(5),
    cl::desc("Maximum depth to recursively prepare pointer data"), cl::Hidden);

static cl::opt<bool> ClNaiveHarness("naive-harness", cl::init(false),
                                    cl::desc("Enable naive harness"),
                                    cl::Hidden);

static cl::list<std::string> ClTypeInfoDirs("type-info-dirs",
                                            cl::CommaSeparated);

void DriverGenerator::initialize(Module &M) {
  this->M = &M;
  C = &M.getContext();
  IRBuilder<> IRB(*C);

  // add function declaration
  DFGetBytes = M.getOrInsertFunction(
      "DFGetBytes", Type::getInt8PtrTy(*C), Type::getInt8PtrTy(*C),
      Type::getInt64Ty(*C), Type::getInt8PtrTy(*C), Type::getInt32Ty(*C));
  DFGetUserCheckCount = M.getOrInsertFunction(
      "DFGetUserCheckCount", Type::getInt64Ty(*C),
      Type::getInt64Ty(*C) /* ele size */, Type::getInt8PtrTy(*C));
  _strlen = M.getOrInsertFunction("strlen", Type::getInt64Ty(*C),
                                  Type::getInt8PtrTy(*C));
  _wcslen = M.getOrInsertFunction("wcslen", Type::getInt64Ty(*C),
                                  Type::getInt32PtrTy(*C));
  DFEnableSetNull = M.getOrInsertFunction(
      "DFEnableSetNull", Type::getInt1Ty(*C), Type::getInt8PtrTy(*C));
  DFManagedMalloc = M.getOrInsertFunction(
      "DFManagedMalloc", Type::getInt8PtrTy(*C), Type::getInt64Ty(*C));
  DFManagedCalloc =
      M.getOrInsertFunction("DFManagedCalloc", Type::getInt8PtrTy(*C),
                            Type::getInt64Ty(*C), Type::getInt64Ty(*C));

  DFGetPtToCntECall = M.getOrInsertFunction(
      "DFGetPtToCntECall", Type::getInt64Ty(*C), Type::getInt64Ty(*C),
      Type::getInt64Ty(*C), Type::getInt64Ty(*C));
  DFGetPtToCntOCall = M.getOrInsertFunction(
      "DFGetPtToCntOCall", Type::getInt64Ty(*C), Type::getInt64Ty(*C),
      Type::getInt64Ty(*C), Type::getInt64Ty(*C));

  DFEnableModifyOCallRet = M.getOrInsertFunction(
      "DFEnableModifyOCallRet", Type::getInt1Ty(*C), Type::getInt8PtrTy(*C));

  // read *.edl.json file
  edlJson = json::parse(ReadFile(ClEdlJsonFile));

  // load json from *.sgxsan.typeinfo.json
  ordered_json TypeJson;
  mDeSerialzer.init(C, TypeJson);
  if (not ClNaiveHarness) {
    for (std::string TypeInfoDir : ClTypeInfoDirs) {
      std::vector<std::string> TypeJsonPaths =
          RecGetFilePaths(TypeInfoDir, ".sgxsan.typeinfo.json");
      for (auto TypeJsonPath : TypeJsonPaths) {
        dbgs() << "== DriverGenerator: Load " << TypeJsonPath << " ==\n";
        TypeJson = ordered_json::parse(ReadFile(TypeJsonPath));
        mDeSerialzer.update(TypeJson);
      }
    }
  }
}

// FOR_LOOP may change insert point of IRBuilder
#define FOR_LOOP_BEG(insert_point, count)                                      \
  Instruction *forBodyTerm = SplitBlockAndInsertIfThen(                        \
      IRB.CreateICmpSGT(count, IRB.getInt64(0), ""), insert_point, false);     \
  IRB.SetInsertPoint(forBodyTerm);                                             \
  PHINode *phi = IRB.CreatePHI(IRB.getInt64Ty(), 2, "");                       \
  phi->addIncoming(IRB.getInt64(0), forBodyTerm->getParent()->getPrevNode());  \
  BasicBlock *forBodyEntry = phi->getParent();

#define FOR_LOOP_END(count)                                                    \
  /*  instrumentParameterCheck may insert new bb, so forBodyTerm may not       \
   * belong to forBodyEntry BB */                                              \
  IRB.SetInsertPoint(forBodyTerm);                                             \
  Value *inc = IRB.CreateAdd(phi, IRB.getInt64(1), "", true, true);            \
  phi->addIncoming(inc, forBodyTerm->getParent());                             \
  ReplaceInstWithInst(                                                         \
      forBodyTerm, BranchInst::Create(forBodyEntry,                            \
                                      forBodyTerm->getParent()->getNextNode(), \
                                      IRB.CreateICmpSLT(inc, count)));

// propagate [in]/[out]/[user_check] to it's element
void DriverGenerator::inheritDirectionAttr(json::json_pointer jsonPtr,
                                           size_t field_index, Type *eleTy) {
  json &Json = edlJson[jsonPtr];
  json &FieldJson = Json["field"][std::to_string(field_index)];
  if (eleTy->isPointerTy() and FieldJson["count"].is_null() and
      FieldJson["size"].is_null()) {
    // Shallow copy
    FieldJson["user_check"] = true;
    return;
  }
  if (Json["user_check"] == true) {
    FieldJson["user_check"] = true;
    // It's user_check, then can't be in, out, or OCallRet
  } else {
    if (Json["in"] == true) {
      FieldJson["in"] = true;
    }
    if (Json["out"] == true) {
      FieldJson["out"] = true;
    }
  }
}

std::string DriverGenerator::RootToken(json::json_pointer ptr) {
  std::string back = "";
  while (not ptr.empty()) {
    back = ptr.back();
    ptr.pop_back();
  }

  return back;
}

bool DriverGenerator::IsECall(json::json_pointer jsonPtr) {
  std::string rootPtrStr = RootToken(jsonPtr);
  if (rootPtrStr == "trusted")
    return true;
  else if (rootPtrStr == "untrusted")
    return false;
  else
    abort();
}

bool DriverGenerator::EnableFuzzInput(json::json_pointer jsonPtr) {
  static std::unordered_map<std::string, bool> map;
  if (map.count(jsonPtr.to_string())) {
    return map[jsonPtr.to_string()];
  }
  bool isEcall = IsECall(jsonPtr);
  bool feedRandom = isEcall;
  json &Json = edlJson[jsonPtr];
  if (Json["user_check"] == true)
    feedRandom = true;
  else if (isEcall) {
    if (Json["in"] == true)
      feedRandom = true;
    else if (Json["out"] == true)
      feedRandom = false;
    // Default => true
  } else {
    if (Json["out"] == true)
      feedRandom = true;
    // Only in / Default => false
  }
  map[jsonPtr.to_string()] = feedRandom;
  return feedRandom;
}

Value *DriverGenerator::createParamContent(
    SmallVector<Type *> types, json::json_pointer jsonPtr,
    std::map<uint64_t, Value *> *paramPtrs, Instruction *insertPt,
    size_t recursion_depth, Value *buffer, bool hasByValAttr) {
  recursion_depth++;
  // get index from json pointer
  size_t idx =
      jsonPtr.back() == "return" ? 0 : std::stoull(jsonPtr.back(), nullptr, 0);
  // we may have prepared this param in other rounds
  if (paramPtrs && paramPtrs->count(idx)) {
    return (*paramPtrs)[idx];
  }
  // show current edl info in json
  // dump(edlJson, jsonPtr);
  // get current type
  auto type = types[idx];
  // prepare a pointer to store content
  IRBuilder<> IRB(insertPt);
  Value *typePtr =
      buffer
          ? buffer
          : IRB.CreatePointerCast(
                IRB.CreateCall(
                    DFManagedCalloc,
                    {IRB.getInt64(1),
                     IRB.getInt64(M->getDataLayout().getTypeAllocSize(type))}),
                PointerType::get(type, 0), "typePtr");
  // use json pointer as node ID
  auto jsonPtrAsID = IRB.CreateGlobalStringPtr(jsonPtr.to_string());
  // Check feed random according to [in]/[out]/[user_check] attribute
  // 1. Originally has attribute
  // 2. Inherited from parent
  bool feedRandom = EnableFuzzInput(jsonPtr);

  // process type case by case, and store content into type pointer
  if (auto pointerTy = dyn_cast<PointerType>(type)) {
    // get element size and type
    auto eleTy = pointerTy->getElementType();
    inheritDirectionAttr(jsonPtr, 0, eleTy);
    if (isa<StructType>(eleTy) and cast<StructType>(eleTy)->isOpaque()) {
      // Opaque element type's pointer must be user_check
      auto OpaqueStructTy = cast<StructType>(eleTy);
      // Recover from json record
      mDeSerialzer.ResolveOpaqueStruct(OpaqueStructTy);
      if (OpaqueStructTy->isOpaque()) {
        // If it's still opaque, replace opaque struct type with uint8
        eleTy = Type::getInt8Ty(*C);
      }
    }
    if (eleTy->isFunctionTy() or
        recursion_depth >= ClMaxRecursionDepthForPointer or
        (ClNaiveHarness and recursion_depth > 1)) {
      // Leave content of typePtr (also is a pointer) 0
    } else {
      size_t _eleSize = M->getDataLayout().getTypeAllocSize(eleTy);
      assert(_eleSize > 0);
      auto eleSize = IRB.getInt64(_eleSize);
      Value *contentPtr = nullptr;
      // if it's a string, directly fill it
      if (edlJson[jsonPtr / "string"] == true or
          edlJson[jsonPtr / "wstring"] == true) {
        // [string/wstring] must exist with [in]
        assert(eleTy->isIntegerTy() and edlJson[jsonPtr / "in"] == true);
        contentPtr = IRB.CreatePointerCast(
            IRB.CreateCall(DFGetBytes,
                           {Constant::getNullValue(IRB.getInt8PtrTy()),
                            IRB.getInt64(0), jsonPtrAsID,
                            IRB.getInt32(edlJson[jsonPtr / "string"] == true
                                             ? FUZZ_STRING
                                             : FUZZ_WSTRING)}),
            pointerTy);
      } else {
        // calculate count of elements the pointer point to
        Value *ptCnt = nullptr;
        if (ClNaiveHarness) {
          ptCnt = IRB.getInt64(1);
        } else {
          // EDL: C array can't be decorated with [count]/[size], and must have
          // it's count
          if (edlJson[jsonPtr / "c_array_count"].is_number()) {
            size_t _c_array_count = edlJson[jsonPtr / "c_array_count"];
            if (_c_array_count <= 0) {
              errs() << "c_array_count must > 0\n";
              abort();
            }
            ptCnt = IRB.getInt64(_c_array_count);
          } else if (edlJson[jsonPtr / "user_check"] == true) {
            ptCnt = IRB.CreateCall(DFGetUserCheckCount, {eleSize, jsonPtrAsID});
          } else {
            Value *count = nullptr, *size = nullptr;
            if (edlJson[jsonPtr / "count"].is_null()) {
              count = IRB.getInt64(1);
            } else if (edlJson[jsonPtr / "count"].is_number()) {
              count = IRB.getInt64(edlJson[jsonPtr / "count"]);
            } else {
              size_t co_param_pos = edlJson[jsonPtr / "count" / "co_param_pos"];
              edlJson[jsonPtr.parent_pointer() / co_param_pos /
                      "isEdlCountAttr"] = true;
              auto co_param_ptr = createParamContent(
                  types, jsonPtr.parent_pointer() / co_param_pos, paramPtrs,
                  insertPt, recursion_depth - 1);
              IRB.SetInsertPoint(insertPt);
              count = IRB.CreateLoad(co_param_ptr->getType()
                                         ->getScalarType()
                                         ->getPointerElementType(),
                                     co_param_ptr);
            }
            if (edlJson[jsonPtr / "size"].is_null()) {
              size = eleSize;
            } else if (edlJson[jsonPtr / "size"].is_number()) {
              // means "size" bytes
              size_t _size = edlJson[jsonPtr / "size"];
              size = IRB.getInt64(_size);
              if (eleTy->isIntegerTy() && _size <= 8) {
                // we can regard it as (size*8)bits integer
                _eleSize = _size;
                eleTy = IRB.getIntNTy(_size * 8);
                eleSize = IRB.getInt64(_size);
              }
            } else {
              size_t co_param_pos = edlJson[jsonPtr / "size" / "co_param_pos"];
              edlJson[jsonPtr.parent_pointer() / co_param_pos /
                      "isEdlSizeAttr"] = true;
              auto co_param_ptr = createParamContent(
                  types, jsonPtr.parent_pointer() / co_param_pos, paramPtrs,
                  insertPt, recursion_depth - 1);
              IRB.SetInsertPoint(insertPt);
              size = IRB.CreateLoad(co_param_ptr->getType()
                                        ->getScalarType()
                                        ->getPointerElementType(),
                                    co_param_ptr);
            }
            ptCnt = IRB.CreateCall(
                DFGetPtToCntECall,
                {IRB.CreateIntCast(size, IRB.getInt64Ty(), false),
                 IRB.CreateIntCast(count, IRB.getInt64Ty(), false), eleSize},
                "ptCnt");
          }
        }

        if (ptCnt == IRB.getInt64(1)) {
          contentPtr = createParamContent({eleTy}, jsonPtr / "field" / 0,
                                          nullptr, insertPt, recursion_depth);
        } else {
          contentPtr = IRB.CreatePointerCast(IRB.CreateCall(DFManagedCalloc,
                                                            {
                                                                ptCnt,
                                                                eleSize,
                                                            }),
                                             PointerType::get(eleTy, 0));
          if (!ClEnableFillAtOnce or hasPointerElement(pointerTy)) {
            // fall back
            FOR_LOOP_BEG(insertPt, ptCnt)
            auto innerInsertPt = &*IRB.GetInsertPoint();
            createParamContent(
                {eleTy}, jsonPtr / "field" / 0, nullptr, innerInsertPt,
                recursion_depth,
                IRB.CreateGEP(eleTy, contentPtr, phi, "typePtr"));
            FOR_LOOP_END(ptCnt)
          } else if (feedRandom) {
            fillAtOnce(contentPtr, jsonPtr, jsonPtrAsID, insertPt, eleTy,
                       ptCnt);
          }
        }
      }
      IRB.SetInsertPoint(insertPt);
      IRB.CreateStore(IRB.CreatePointerCast(contentPtr, pointerTy), typePtr);
      if (feedRandom and not hasByValAttr) {
        // we call function to query whether fill pointer with meaningful
        // address or not
        Instruction *term = SplitBlockAndInsertIfThen(
            IRB.CreateCall(DFEnableSetNull, jsonPtrAsID), insertPt, false);
        IRB.SetInsertPoint(term);
        // Set it back to 0
        IRB.CreateStore(Constant::getNullValue(pointerTy), typePtr);
      }
    }
  } else if (auto structTy = dyn_cast<StructType>(type)) {
    if (not ClNaiveHarness and
        (!ClEnableFillAtOnce or hasPointerElement(structTy))) {
      // fall back
      // structure's member pointers may have size/count attributes(deep copy),
      // so we have to prepare a map to record
      std::map<uint64_t, Value *> preparedSubFieldParamPtrs;
      SmallVector<Type *> StructElementTypes{structTy->elements().begin(),
                                             structTy->elements().end()};
      for (size_t index = 0; index < structTy->getNumElements(); index++) {
        inheritDirectionAttr(jsonPtr, index, structTy->getElementType(index));
        IRB.SetInsertPoint(insertPt);
        createParamContent(
            StructElementTypes, jsonPtr / "field" / index,
            &preparedSubFieldParamPtrs, insertPt, recursion_depth,
            IRB.CreateGEP(type, typePtr, {IRB.getInt32(0), IRB.getInt32(index)},
                          "typePtr"));
      }
    } else if (feedRandom) {
      fillAtOnce(typePtr, jsonPtr, jsonPtrAsID, insertPt);
    }
  } else if (auto arrTy = dyn_cast<ArrayType>(type)) {
    auto eleTy = arrTy->getElementType();
    inheritDirectionAttr(jsonPtr, 0, eleTy);
    auto eleCnt = IRB.getInt64(arrTy->getNumElements());
    if (not ClNaiveHarness and
        (!ClEnableFillAtOnce or hasPointerElement(arrTy))) {
      // fall back
      FOR_LOOP_BEG(insertPt, eleCnt)
      auto innerInsertPt = &*IRB.GetInsertPoint();
      IRB.SetInsertPoint(innerInsertPt);
      createParamContent(
          {eleTy}, jsonPtr / "field" / 0, nullptr, innerInsertPt,
          recursion_depth,
          IRB.CreateGEP(type, typePtr, {IRB.getInt32(0), phi}, "typePtr"));
      FOR_LOOP_END(eleCnt)
    } else if (feedRandom) {
      fillAtOnce(typePtr, jsonPtr, jsonPtrAsID, insertPt);
    }
  } else if (feedRandom) {
    assert(not isa<VectorType>(type) and not isa<FunctionType>(type));
    fillAtOnce(typePtr, jsonPtr, jsonPtrAsID, insertPt);
  }

  if (paramPtrs)
    (*paramPtrs)[idx] = typePtr;
  return typePtr;
}

bool DriverGenerator::IsOCallReturn(json::json_pointer jsonPtr) {
  if (not IsECall(jsonPtr)) {
    while (not jsonPtr.empty()) {
      if (jsonPtr.back() == "return") {
        return true;
      }
      jsonPtr = jsonPtr.parent_pointer();
    }
  }
  return false;
}

void DriverGenerator::fillAtOnce(Value *dstPtr, json::json_pointer jsonPtr,
                                 Value *jsonPtrAsID, Instruction *insertPt,
                                 Type *type, Value *arrCnt, bool isOcall) {
  assert(dstPtr && insertPt && dstPtr->getType()->isPointerTy());
  if (type == nullptr)
    type = dstPtr->getType()->getPointerElementType();
  IRBuilder<> IRB(insertPt);
  size_t _tySize = M->getDataLayout().getTypeAllocSize(type);
  assert(_tySize > 0);
  Value *tySize = IRB.getInt64(_tySize);
  FuzzDataTy byteType = edlJson[jsonPtr / "isEdlSizeAttr"] == true ? FUZZ_SIZE
                        : edlJson[jsonPtr / "isEdlCountAttr"] == true
                            ? FUZZ_COUNT
                        : IsOCallReturn(jsonPtr)           ? FUZZ_RET
                        : (isa<ArrayType>(type) or arrCnt) ? FUZZ_ARRAY
                        : isa<StructType>(type)            ? FUZZ_DATA
                                                           : FUZZ_DATA;
  if (arrCnt) {
    tySize = IRB.CreateMul(tySize, arrCnt);
  }
  IRB.CreateCall(DFGetBytes, {IRB.CreatePointerCast(dstPtr, IRB.getInt8PtrTy()),
                              tySize, jsonPtrAsID, IRB.getInt32(byteType)});
}

bool DriverGenerator::hasPointerElement(Type *type) {
  if (typeHasPointerMap.count(type))
    return typeHasPointerMap[type];
  bool result = _hasPointerElement(type);
  typeHasPointerMap[type] = result;
  return result;
}

bool DriverGenerator::_hasPointerElement(Type *type, size_t level) {
  bool result = false;
  // start from 1
  level++;
  if (auto ptrTy = dyn_cast<PointerType>(type)) {
    result =
        level == 1 ? _hasPointerElement(ptrTy->getElementType(), level) : true;
  } else if (auto structTy = dyn_cast<StructType>(type)) {
    for (auto eleTy : structTy->elements()) {
      if (_hasPointerElement(eleTy, level)) {
        result = true;
        break;
      }
    }
  } else if (auto arrTy = dyn_cast<ArrayType>(type)) {
    result = _hasPointerElement(arrTy->getElementType(), level);
  } else if (isa<FunctionType>(type)) {
    // don't prepare data for function type as well
    abort();
  }
  return result;
}

Function *DriverGenerator::createEcallFuzzWrapperFunc(std::string ecallName) {
  // create empty fuzz_ecall_xxx() function
  auto ecallToBeFuzzed = M->getFunction(ecallName);
  assert(ecallToBeFuzzed &&
         M->getFunction(ClWrapperFuzzECallPrefix + ecallName) == nullptr);

  auto WrapperFuzzEcallCallee = M->getOrInsertFunction(
      ClWrapperFuzzECallPrefix + ecallName, Type::getInt32Ty(*C));
  auto WrapperFuzzEcall = cast<Function>(WrapperFuzzEcallCallee.getCallee());
  auto EntryBB = BasicBlock::Create(*C, "EntryBB", WrapperFuzzEcall);
  auto retVoidI = ReturnInst::Create(*C, EntryBB);

  // start to fill code
  std::map<uint64_t, Value *> preparedParamPtrs;
  // 1. get all parameter types and return paramter(ECall will use pointer of
  // return as second parameter, while the first parameter is Enclave ID), in
  // case of corelative parameter's preparation
  SmallVector<Type *> paramTypes;
  Argument *returnParamPtrArg = nullptr;
  for (auto &arg : ecallToBeFuzzed->args()) {
    if (arg.getArgNo() == 0)
      // it's eid parameter
      continue;
    else if (arg.getArgNo() == 1 &&
             (edlJson["trusted"][ecallName]["return"]["type"] != "void"))
      // it's pointer of return parameter
      returnParamPtrArg = &arg;
    else
      paramTypes.push_back(arg.getType());
  }
  // 2. prepare all parameters, and save their pointer
  size_t edlParamNo = 0;
  for (auto &arg : ecallToBeFuzzed->args()) {
    auto argNo = arg.getArgNo();
    if (argNo == 0 /* it's eid parameter */ or
        (argNo == 1 && (edlJson["trusted"][ecallName]["return"]["type"] !=
                        "void")) /* it's pointer of return parameter */)
      continue;
    else {
      // it's a parameter declareted at edl file
      json::json_pointer jsonPtr = json::json_pointer("/trusted") / ecallName /
                                   "parameter" / edlParamNo++;
      createParamContent(paramTypes, jsonPtr, &preparedParamPtrs, retVoidI, 0,
                         nullptr, arg.hasByValAttr());
    }
  }
  // 3. prepare Enclave ID parameter
  auto eid = cast<GlobalVariable>(M->getOrInsertGlobal(
      "__hidden_sgxfuzzer_harness_global_eid", Type::getInt64Ty(*C)));
  eid->setLinkage(GlobalValue::ExternalLinkage);
  IRBuilder<> IRB(retVoidI);
  SmallVector<Value *> preparedParams = {
      IRB.CreateLoad(Type::getInt64Ty(*C), eid)};
  // 4. prepare return parameter
  if (returnParamPtrArg) {
    json::json_pointer jsonPtr =
        json::json_pointer("/trusted") / ecallName / "return";
    edlJson[jsonPtr / "user_check"] = true;
    auto returnParamPtr = createParamContent({returnParamPtrArg->getType()},
                                             jsonPtr, nullptr, retVoidI);
    IRB.SetInsertPoint(retVoidI);
    preparedParams.push_back(IRB.CreateLoad(
        returnParamPtr->getType()->getScalarType()->getPointerElementType(),
        returnParamPtr));
  }
  // 5. get prepared parameters from their pointers
  for (size_t argPos = 0; argPos < preparedParamPtrs.size(); argPos++) {
    preparedParams.push_back(IRB.CreateLoad(preparedParamPtrs[argPos]
                                                ->getType()
                                                ->getScalarType()
                                                ->getPointerElementType(),
                                            preparedParamPtrs[argPos]));
  }
  // 6. call ECall
  auto callEcall = IRB.CreateCall(ecallToBeFuzzed, preparedParams);
  IRB.CreateRet(callEcall);
  retVoidI->eraseFromParent();
  return WrapperFuzzEcall;
}

// create content for ocall [out] pointer parameters
void DriverGenerator::saveCreatedInput2OCallPtrParam(Function *ocallWapper,
                                                     std::string realOCallName,
                                                     Instruction *insertPt) {
  for (auto &arg : ocallWapper->args()) {
    auto idx = arg.getArgNo();
    if (auto pointerTy = dyn_cast<PointerType>(arg.getType())) {
      json::json_pointer jsonPtr("/untrusted/" + realOCallName + "/parameter/" +
                                 std::to_string(idx));
      // TODO: If ocall pointer is [user_check] and point to memory outside
      // Enclave
      if (edlJson[jsonPtr / "out"] == true) {
        // dump(edlJson, jsonPtr);
        auto eleTy = pointerTy->getElementType();
        inheritDirectionAttr(jsonPtr, 0, eleTy);
        IRBuilder<> IRB(insertPt);

        auto jsonPtrAsID = IRB.CreateGlobalStringPtr(jsonPtr.to_string());

        // Only OCall parameter is not a nullptr and allowed to modify
        auto ptrCanSet = SplitBlockAndInsertIfThen(
            IRB.CreateLogicalAnd(
                IRB.CreateICmpNE(IRB.CreatePtrToInt(&arg, IRB.getInt64Ty()),
                                 ConstantInt::getNullValue(IRB.getInt64Ty())),
                IRB.CreateCall(DFEnableModifyOCallRet, {jsonPtrAsID})),
            insertPt, false);
        insertPt = ptrCanSet;
        IRB.SetInsertPoint(insertPt);

        if (isa<StructType>(eleTy) and cast<StructType>(eleTy)->isOpaque()) {
          auto OpaqueStructTy = cast<StructType>(eleTy);
          // Recover from json record
          mDeSerialzer.ResolveOpaqueStruct(OpaqueStructTy);
          if (OpaqueStructTy->isOpaque()) {
            // If it's still opaque, replace opaque struct type with uint8F
            eleTy = Type::getInt8Ty(*C);
          }
        }
        size_t _eleSize = M->getDataLayout().getTypeAllocSize(eleTy);
        assert(_eleSize > 0);
        auto eleSize = IRB.getInt64(_eleSize);
        // if it's a string, directly fill it
        if (edlJson[jsonPtr / "string"] == true or
            edlJson[jsonPtr / "wstring"] == true) {
          // [string/wstring] must exist with [in]
          assert(eleTy->isIntegerTy() and edlJson[jsonPtr / "in"] == true);

          // Max string length is length of original string pointer
          if (edlJson[jsonPtr / "string"] == true) {
            Value *StrLen = IRB.CreateCall(
                _strlen, IRB.CreatePointerCast(&arg, IRB.getInt8PtrTy()));
            IRB.CreateCall(DFGetBytes,
                           {IRB.CreatePointerCast(&arg, IRB.getInt8PtrTy()),
                            StrLen, jsonPtrAsID, IRB.getInt32(FUZZ_STRING)});
          } else {
            Value *StrLen = IRB.CreateCall(
                _wcslen, IRB.CreatePointerCast(
                             &arg, PointerType::get(IRB.getInt32Ty(), 0)));
            IRB.CreateCall(DFGetBytes,
                           {IRB.CreatePointerCast(&arg, IRB.getInt8PtrTy()),
                            StrLen, jsonPtrAsID, IRB.getInt32(FUZZ_WSTRING)});
          }
        } else {
          // calculate count of elements the pointer point to
          Value *ptCnt = nullptr;
          if (ClNaiveHarness) {
            ptCnt = IRB.getInt64(1);
          } else {
            // EDL: c array can't be decorated with [count]/[size], and must
            // have it's count
            if (edlJson[jsonPtr / "c_array_count"].is_number()) {
              ptCnt = IRB.getInt64(edlJson[jsonPtr / "c_array_count"]);
            } else {
              Value *count =
                  edlJson[jsonPtr / "count"].is_null() ? IRB.getInt64(1)
                  : edlJson[jsonPtr / "count"].is_number()
                      ? cast<Value>(IRB.getInt64(edlJson[jsonPtr / "count"]))
                      : IRB.CreateIntCast(
                            ocallWapper->getArg(
                                edlJson[jsonPtr / "count" / "co_param_pos"]),
                            Type::getInt64Ty(*C), false);
              Value *size = nullptr;
              if (edlJson[jsonPtr / "size"].is_null()) {
                size = eleSize;
              } else if (edlJson[jsonPtr / "size"].is_number()) {
                // means "size" bytes
                size_t _size = edlJson[jsonPtr / "size"];
                size = IRB.getInt64(_size);
                if (eleTy->isIntegerTy() && _size <= 8) {
                  // we can regard it as (size*8)bits integer
                  _eleSize = _size;
                  eleTy = IRB.getIntNTy(_size * 8);
                  eleSize = IRB.getInt64(_size);
                }
              } else {
                size = IRB.CreateIntCast(
                    ocallWapper->getArg(
                        edlJson[jsonPtr / "size" / "co_param_pos"]),
                    Type::getInt64Ty(*C), false);
              }
              ptCnt = IRB.CreateCall(DFGetPtToCntOCall, {size, count, eleSize},
                                     "ptCnt");
            }
          }

          if (ptCnt == IRB.getInt64(1)) {
            createParamContent({eleTy}, jsonPtr / "field" / 0, nullptr,
                               insertPt, 1, &arg);
          } else {
            if (!ClEnableFillAtOnce or hasPointerElement(pointerTy)) {
              // fall back
              FOR_LOOP_BEG(insertPt, ptCnt)
              auto innerInsertPt = &*IRB.GetInsertPoint();
              IRB.SetInsertPoint(innerInsertPt);
              createParamContent(
                  {eleTy}, jsonPtr / "field" / 0, nullptr, innerInsertPt, 1,
                  IRB.CreateGEP(
                      arg.getType()->getScalarType()->getPointerElementType(),
                      &arg, phi));
              FOR_LOOP_END(ptCnt)
            } else {
              fillAtOnce(&arg, jsonPtr, jsonPtrAsID, insertPt, eleTy, ptCnt,
                         true);
            }
          }
        }
      }
    }
  }
}

void DriverGenerator::createOcallFunc(std::string realOCallName) {
  auto realOCall = M->getFunction(realOCallName);
  // create empty ocall wrapper function
  FunctionCallee ocallWrapperCallee = M->getOrInsertFunction(
      ClOCallWrapperPrefix + realOCallName, realOCall->getFunctionType());
  Function *ocallWrapper = cast<Function>(ocallWrapperCallee.getCallee());
  auto EntryBB = BasicBlock::Create(*C, "EntryBB", ocallWrapper);
  // create return void instruction as insert point
  IRBuilder<> IRB(EntryBB);
  auto retVoidI = IRB.CreateRetVoid();

  // Call real OCall in wrapper
  SmallVector<Value *> args;
  for (auto &arg : ocallWrapper->args()) {
    args.push_back(&arg);
  }
  IRB.SetInsertPoint(retVoidI);
  auto RealOCallRet =
      IRB.CreateCall(realOCall->getFunctionType(), realOCall, args);
  auto funcRetType = ocallWrapper->getReturnType();
  ReturnInst *retI = nullptr;
  if (funcRetType->isVoidTy()) {
    retI = retVoidI;
  } else {
    auto jsonPtr = json::json_pointer("/untrusted") / realOCallName / "return";
    edlJson[jsonPtr / "user_check"] = true;
    IRB.SetInsertPoint(retVoidI);
    auto JsonPtrStr = IRB.CreateGlobalStringPtr(jsonPtr.to_string());
    auto EnableModifyOCallRet =
        IRB.CreateCall(DFEnableModifyOCallRet, {JsonPtrStr});
    Instruction *ModifyOCallRetTerm =
        SplitBlockAndInsertIfThen(EnableModifyOCallRet, retVoidI, false);

    // Construct ModifyOCallRet BB
    auto retValuePtr =
        createParamContent({funcRetType}, jsonPtr, nullptr, ModifyOCallRetTerm);
    IRB.SetInsertPoint(ModifyOCallRetTerm);
    auto retVal = IRB.CreateLoad(
        retValuePtr->getType()->getScalarType()->getPointerElementType(),
        retValuePtr);

    // Set return value
    IRB.SetInsertPoint(retVoidI);
    auto phi = IRB.CreatePHI(funcRetType, 2, "phi");
    phi->addIncoming(RealOCallRet, EnableModifyOCallRet->getParent());
    phi->addIncoming(retVal, ModifyOCallRetTerm->getParent());
    retI = IRB.CreateRet(phi);
    retVoidI->eraseFromParent();
  }
  retVoidI = nullptr;

  saveCreatedInput2OCallPtrParam(ocallWrapper, realOCallName, retI);
}

void DriverGenerator::passStaticAnalysisResultToRuntime(
    SmallVector<Constant *> &ecallFuzzWrapperFuncs) {
  IRBuilder<> IRB(*C);

  // create a global int to store number of ecall
  auto _ecallNum = ecallFuzzWrapperFuncs.size();
  auto ecallNum = cast<GlobalVariable>(
      M->getOrInsertGlobal("gFuzzECallNum", Type::getInt32Ty(*C)));
  ecallNum->setInitializer(ConstantInt::get(IRB.getInt32Ty(), _ecallNum));

  // create a global array to store all ecall fuzz wrappers
  auto ecallFuzzWrapperFuncPtrArrayType = ArrayType::get(
      FunctionType::get(IRB.getInt32Ty(), false)->getPointerTo(), _ecallNum);
  auto globalEcallFuzzWrappers = cast<GlobalVariable>(M->getOrInsertGlobal(
      "gFuzzECallArray", ecallFuzzWrapperFuncPtrArrayType));
  globalEcallFuzzWrappers->setInitializer(ConstantArray::get(
      ecallFuzzWrapperFuncPtrArrayType, ecallFuzzWrapperFuncs));

  // create a global array of string to store names of all ecall fuzz wrappers
  auto ecallFuzzWrapperNameArrTy =
      ArrayType::get(IRB.getInt8PtrTy(), _ecallNum);
  auto globalEcallFuzzWrapperNameArr = cast<GlobalVariable>(
      M->getOrInsertGlobal("gFuzzECallNameArray", ecallFuzzWrapperNameArrTy));
  SmallVector<Constant *> wrapperNames;
  for (auto fuzzWrapper : ecallFuzzWrapperFuncs) {
    wrapperNames.push_back(IRB.CreateGlobalStringPtr(
        cast<Function>(fuzzWrapper)->getName(), "", 0, M));
  }
  globalEcallFuzzWrapperNameArr->setInitializer(
      ConstantArray::get(ecallFuzzWrapperNameArrTy, wrapperNames));
}

void DriverGenerator::hookOCallWithWrapper(
    Module &M,
    SmallVector<std::string>
        filteredOCallNames) { // Collect all CallInst in current Module
  SmallVector<CallInst *> CIs = mInstVisitor.visitModule(M).CallInstVec;

  // Replace OCall with wrapper
  for (auto CI : CIs) {
    if (auto callee = getCalledFunctionStripPointerCast(CI)) {
      std::string calleeName = callee->getName().str();
      if (std::find_if(filteredOCallNames.begin(), filteredOCallNames.end(),
                       [calleeName](std::string str) {
                         return str == calleeName;
                       }) != filteredOCallNames.end()) {
        // Declare wrapper
        FunctionCallee ocallWrapperCallee = M.getOrInsertFunction(
            ClOCallWrapperPrefix + calleeName, callee->getFunctionType());

        // get CI arguments
        SmallVector<Value *> CIOps;
        for (auto &arg : CI->args()) {
          CIOps.push_back(arg.get());
        }

        // Replace it
        IRBuilder<> IRB(CI);
        CallInst *wrapperCI = IRB.CreateCall(ocallWrapperCallee, CIOps);
        CI->replaceAllUsesWith(wrapperCI);
        CI->eraseFromParent();
      }
    }
  }
}

bool isAtUBridge(Module &M) {
  for (auto &GV : M.globals()) {
    if (GV.getName().contains("ocall_table_")) {
      return true;
    }
  }
  return false;
}

bool DriverGenerator::runOnModule(Module &M) {
  if (not isAtUBridge(M)) {
    // dbgs() << M.getName() << " isn't a UBridge\n";
    return false;
  }
  dbgs() << "== DriverGenerator: " << M.getName() << " ==\n";
  initialize(M);

  // Collect all OCalls' names except it start with sgxsan_ocall_
  SmallVector<std::string> filteredOCallNames;
  for (auto &ocallInfo : edlJson["untrusted"].items()) {
    std::string ocallName = ocallInfo.key();
    if (StringRef(ocallName).startswith("sgxsan_ocall_"))
      continue;
    filteredOCallNames.push_back(ocallName);
  }

  hookOCallWithWrapper(M, filteredOCallNames);

  // create wrapper functions used to fuzz ecall
  SmallVector<Constant *> ecallFuzzWrapperFuncs;
  for (auto &ecallInfo : edlJson["trusted"].items()) {
    std::string ecallName = ecallInfo.key();
    if (StringRef(ecallName).startswith("sgxsan_ecall_"))
      continue;
    ecallFuzzWrapperFuncs.push_back(createEcallFuzzWrapperFunc(ecallName));
  }

  // create ocalls
  for (auto ocallName : filteredOCallNames) {
    createOcallFunc(ocallName);
  }
  // at the end
  passStaticAnalysisResultToRuntime(ecallFuzzWrapperFuncs);
  return true;
}
