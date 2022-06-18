#include "AddressSanitizer.hpp"
#include "FunctionStackPoisoner.hpp"
#include "SGXSanInstVisitor.hpp"
#include <utility>
#include <tuple>

using namespace llvm;

const char kAsanReportErrorTemplate[] = "__asan_report_";
const char kAsanHandleNoReturnName[] = "__asan_handle_no_return";

// This flag may need to be replaced with -f[no-]asan-reads.
static cl::opt<bool> ClInstrumentReads(
    "sgxsan-instrument-reads",
    cl::desc("instrument read instructions"),
    cl::Hidden,
    cl::init(true));

static cl::opt<bool> ClInstrumentWrites(
    "sgxsan-instrument-writes",
    cl::desc("instrument write instructions"),
    cl::Hidden,
    cl::init(true));

static cl::opt<bool> ClInstrumentAtomics(
    "sgxsan-instrument-atomics",
    cl::desc("instrument atomic instructions (rmw, cmpxchg)"),
    cl::Hidden,
    cl::init(true));

static cl::opt<bool> ClInstrumentByval(
    "sgxsann-instrument-byval",
    cl::desc("instrument byval call arguments"),
    cl::Hidden,
    cl::init(true));

static cl::opt<int> ClInstrumentationWithCallsThreshold(
    "sgxsan-instrumentation-with-call-threshold",
    cl::desc(
        "If the function being instrumented contains more than "
        "this number of memory accesses, use callbacks instead of "
        "inline checks (-1 means never use callbacks)."),
    cl::Hidden,
    cl::init(7000));

static cl::opt<std::string> ClMemoryAccessCallbackPrefix(
    "sgxsan-memory-access-callback-prefix",
    cl::desc("Prefix for memory access callbacks"),
    cl::Hidden,
    cl::init("__asan_"));

static cl::opt<bool> ClSkipPromotableAllocas(
    "sgxsan-skip-promotable-allocas",
    cl::desc("Do not instrument promotable allocas"),
    cl::Hidden,
    cl::init(true));

// This flag limits the number of instructions to be instrumented
// in any given BB. Normally, this should be set to unlimited (INT_MAX),
// but due to http://llvm.org/bugs/show_bug.cgi?id=12652 we temporary
// set it to 10000.
static cl::opt<int> ClMaxInsnsToInstrumentPerBB(
    "sgxsan-max-ins-per-bb",
    cl::init(10000),
    cl::desc("maximal number of instructions to instrument in any given BB"),
    cl::Hidden);

static cl::opt<bool> ClUseAfterScope(
    "sgxsan-use-after-scope",
    cl::desc("Check stack-use-after-scope"),
    cl::Hidden,
    cl::init(true));

static cl::opt<bool> ClAlwaysSlowPath(
    "sgxsan-always-slow-path",
    cl::desc("use instrumentation with slow path for all accesses"),
    cl::Hidden,
    cl::init(true));

bool isFuncAtEnclaveTBridge = false;

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");

AddressSanitizer::AddressSanitizer(Module &M, bool UseAfterScope)
    : UseAfterScope(UseAfterScope || ClUseAfterScope)
{
    C = &(M.getContext());
    LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    Mapping = getShadowMapping();
}

void AddressSanitizer::initializeCallbacks(Module &M)
{
    IRBuilder<> IRB(*C);
    // Create __asan_report* callbacks.
    // IsWrite and TypeSize are encoded in the function name.

    AsanMemoryAccessCallbackSizedLoad = M.getOrInsertFunction(ClMemoryAccessCallbackPrefix + "LoadN",
                                                              IRB.getVoidTy(), IntptrTy, IntptrTy, IRB.getInt1Ty(), IRB.getInt8PtrTy());
    AsanMemoryAccessCallbackSizedStore = M.getOrInsertFunction(ClMemoryAccessCallbackPrefix + "StoreN",
                                                               IRB.getVoidTy(), IntptrTy, IntptrTy);

    for (size_t AccessIsWrite = 0; AccessIsWrite <= 1; AccessIsWrite++)
    {
        const std::string TypeStr = AccessIsWrite ? "store" : "load";

        SmallVector<Type *, 3> Args2 = {IntptrTy, IntptrTy};
        SmallVector<Type *, 2> Args1{1, IntptrTy};

        AsanErrorCallbackSized[AccessIsWrite] = M.getOrInsertFunction(
            kAsanReportErrorTemplate + TypeStr + "_n",
            FunctionType::get(IRB.getVoidTy(), Args2, false));

        for (size_t AccessSizeIndex = 0; AccessSizeIndex < kNumberOfAccessSizes;
             AccessSizeIndex++)
        {
            const std::string Suffix = TypeStr + itostr(1ULL << AccessSizeIndex);
            AsanErrorCallback[AccessIsWrite][AccessSizeIndex] =
                M.getOrInsertFunction(
                    kAsanReportErrorTemplate + Suffix,
                    FunctionType::get(IRB.getVoidTy(), Args1, false));

            AsanMemoryAccessCallback[AccessIsWrite][AccessSizeIndex] =
                M.getOrInsertFunction(
                    ClMemoryAccessCallbackPrefix + Suffix,
                    FunctionType::get(IRB.getVoidTy(), Args1, false));
        }
    }

    const std::string MemIntrinCallbackPrefix = ClMemoryAccessCallbackPrefix;
    AsanMemmove = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memmove",
                                        IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                        IRB.getInt8PtrTy(), IntptrTy);
    AsanMemcpy = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memcpy",
                                       IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                       IRB.getInt8PtrTy(), IntptrTy);
    AsanMemset = M.getOrInsertFunction(MemIntrinCallbackPrefix + "memset",
                                       IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
                                       IRB.getInt32Ty(), IntptrTy);

    // AsanHandleNoReturnFunc =
    //     M.getOrInsertFunction(kAsanHandleNoReturnName, IRB.getVoidTy());

    // declare extern elrange symbol
    declareExternElrangeSymbol(M);

    EnclaveTLSConstructorAtTBridgeBegin = M.getOrInsertFunction("EnclaveTLSConstructorAtTBridgeBegin", IRB.getVoidTy());
    EnclaveTLSDestructorAtTBridgeEnd = M.getOrInsertFunction("EnclaveTLSDestructorAtTBridgeEnd", IRB.getVoidTy());

    WhitelistOfAddrOutEnclave_active = M.getOrInsertFunction("WhitelistOfAddrOutEnclave_active", IRB.getVoidTy());
    WhitelistOfAddrOutEnclave_deactive = M.getOrInsertFunction("WhitelistOfAddrOutEnclave_deactive", IRB.getVoidTy());
    WhitelistOfAddrOutEnclave_query_ex = M.getOrInsertFunction("WhitelistOfAddrOutEnclave_query_ex",
                                                               IRB.getVoidTy(), IRB.getInt8PtrTy(), IntptrTy,
                                                               IRB.getInt1Ty(), IRB.getInt1Ty(), IRB.getInt8PtrTy());
    WhitelistOfAddrOutEnclave_add_in_enclave_access_cnt = M.getOrInsertFunction("WhitelistOfAddrOutEnclave_add_in_enclave_access_cnt", IRB.getVoidTy());
    WhitelistOfAddrOutEnclave_global_propagate = M.getOrInsertFunction("WhitelistOfAddrOutEnclave_global_propagate",
                                                                       IRB.getVoidTy(), IRB.getInt8PtrTy());
    sgxsan_edge_check = M.getOrInsertFunction("sgxsan_edge_check", IRB.getVoidTy(),
                                              IRB.getInt8PtrTy(), IRB.getInt64Ty(), IRB.getInt32Ty());
    SGXSanMemcpyS = M.getOrInsertFunction("sgxsan_memcpy_s", IRB.getInt32Ty(), IRB.getInt8PtrTy(),
                                          IRB.getInt64Ty(), IRB.getInt8PtrTy(), IRB.getInt64Ty());
    SGXSanMemsetS = M.getOrInsertFunction("sgxsan_memset_s", IRB.getInt32Ty(), IRB.getInt8PtrTy(),
                                          IRB.getInt64Ty(), IRB.getInt32Ty(), IRB.getInt64Ty());
    SGXSanMemmoveS = M.getOrInsertFunction("sgxsan_memmove_s", IRB.getInt32Ty(), IRB.getInt8PtrTy(),
                                           IRB.getInt64Ty(), IRB.getInt8PtrTy(), IRB.getInt64Ty());
#if (USE_SGXSAN_MALLOC)
    SGXSanMalloc = M.getOrInsertFunction("sgxsan_malloc", IRB.getInt8PtrTy(), IRB.getInt64Ty());
    SGXSanFree = M.getOrInsertFunction("sgxsan_free", IRB.getVoidTy(), IRB.getInt8PtrTy());
    SGXSanCalloc = M.getOrInsertFunction("sgxsan_calloc", IRB.getInt8PtrTy(), IRB.getInt64Ty(), IRB.getInt64Ty());
    SGXSanRealloc = M.getOrInsertFunction("sgxsan_realloc", IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IRB.getInt64Ty());
#endif

    get_mmap_infos = M.getOrInsertFunction("get_mmap_infos", IRB.getVoidTy());
    is_pointer_readable = M.getOrInsertFunction("is_pointer_readable", IRB.getInt1Ty(), IRB.getInt8PtrTy(), IntptrTy, IRB.getInt32Ty());
}

void AddressSanitizer::getInterestingMemoryOperands(
    Instruction *I, SmallVectorImpl<InterestingMemoryOperand> &Interesting, SmallVector<StoreInst *, 16> &GlobalVariableStoreInsts)
{
    // Skip memory accesses inserted by another instrumentation.
    if (I->hasMetadata("nosanitize"))
        return;

    if (LoadInst *LI = dyn_cast<LoadInst>(I))
    {
        if (!ClInstrumentReads || ignoreAccess(LI->getPointerOperand()))
            return;
        Interesting.emplace_back(I, LI->getPointerOperandIndex(), false,
                                 LI->getType(), LI->getAlign());
    }
    else if (StoreInst *SI = dyn_cast<StoreInst>(I))
    {
        if (!ClInstrumentWrites || ignoreAccess(SI->getPointerOperand()))
            return;
        if (isa<GlobalVariable>(SI->getPointerOperand()))
        {
            GlobalVariableStoreInsts.emplace_back(SI);
        }
        else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(SI->getPointerOperand()))
        {
            if (CE->getOpcode() == Instruction::GetElementPtr)
            {
                if (isa<GlobalVariable>(CE->getOperand(0)))
                {
                    GlobalVariableStoreInsts.emplace_back(SI);
                }
            }
        }
        Interesting.emplace_back(I, SI->getPointerOperandIndex(), true,
                                 SI->getValueOperand()->getType(), SI->getAlign());
    }
    else if (AtomicRMWInst *RMW = dyn_cast<AtomicRMWInst>(I))
    {
        if (!ClInstrumentAtomics || ignoreAccess(RMW->getPointerOperand()))
            return;
        Interesting.emplace_back(I, RMW->getPointerOperandIndex(), true,
                                 RMW->getValOperand()->getType(), None);
    }
    else if (AtomicCmpXchgInst *XCHG = dyn_cast<AtomicCmpXchgInst>(I))
    {
        if (!ClInstrumentAtomics || ignoreAccess(XCHG->getPointerOperand()))
            return;
        Interesting.emplace_back(I, XCHG->getPointerOperandIndex(), true,
                                 XCHG->getCompareOperand()->getType(), None);
    }
    else if (auto CI = dyn_cast<CallInst>(I))
    {
        auto calleeName = getDirectCalleeName(CI);
        if (calleeName.startswith("llvm.masked.load.") ||
            calleeName.startswith("llvm.masked.store."))
        {
            // bool IsWrite = F->getName().startswith("llvm.masked.store.");
            // // Masked store has an initial operand for the value.
            // unsigned OpOffset = IsWrite ? 1 : 0;
            // if (IsWrite ? !ClInstrumentWrites : !ClInstrumentReads)
            //     return;

            // auto BasePtr = CI->getOperand(OpOffset);
            // if (ignoreAccess(BasePtr))
            //     return;
            // auto Ty = cast<PointerType>(BasePtr->getType())->getElementType();
            // MaybeAlign Alignment = Align(1);
            // // Otherwise no alignment guarantees. We probably got Undef.
            // if (auto *Op = dyn_cast<ConstantInt>(CI->getOperand(1 + OpOffset)))
            //     Alignment = Op->getMaybeAlignValue();
            // Value *Mask = CI->getOperand(2 + OpOffset);
            // Interesting.emplace_back(I, OpOffset, IsWrite, Ty, Alignment, Mask);
        }
        else
        {
            for (unsigned ArgNo = 0; ArgNo < CI->getNumArgOperands(); ArgNo++)
            {
                if (!ClInstrumentByval || !CI->isByValArgument(ArgNo) ||
                    ignoreAccess(CI->getArgOperand(ArgNo)))
                    continue;
                Type *Ty = CI->getParamByValType(ArgNo);
                Interesting.emplace_back(I, ArgNo, false, Ty, Align(1));
            }
        }
    }
}

Value *AddressSanitizer::memToShadow(Value *Shadow, IRBuilder<> &IRB)
{
    // as shadow memory only map elrange, let Shadow - EnclaveBase
    // EnclaveBase have to be initialied before here
    // check instrumentation is before poison operation
    Shadow = IRB.CreateSub(Shadow, SGXSanEnclaveBase);

    // Shadow >> scale
    Shadow = IRB.CreateLShr(Shadow, Mapping.Scale);
    if (Mapping.Offset == 0)
        return Shadow;

    // (Shadow >> scale) + offset
    Value *ShadowBase;

    ShadowBase = ConstantInt::get(IntptrTy, Mapping.Offset);

    return IRB.CreateAdd(Shadow, ShadowBase);
}

Value *AddressSanitizer::createSlowPathCmp(IRBuilder<> &IRB, Value *AddrLong,
                                           Value *ShadowValue,
                                           uint32_t TypeSize)
{
    size_t Granularity = static_cast<size_t>(1) << Mapping.Scale;
    // Addr & (Granularity - 1)
    Value *LastAccessedByte =
        IRB.CreateAnd(AddrLong, ConstantInt::get(IntptrTy, Granularity - 1));
    // (Addr & (Granularity - 1)) + size - 1
    if (TypeSize / 8 > 1)
        LastAccessedByte = IRB.CreateAdd(
            LastAccessedByte, ConstantInt::get(IntptrTy, TypeSize / 8 - 1));
    // (uint8_t) ((Addr & (Granularity-1)) + size - 1)
    LastAccessedByte =
        IRB.CreateIntCast(LastAccessedByte, ShadowValue->getType(), false);
    // ((uint8_t) ((Addr & (Granularity-1)) + size - 1)) >= ShadowValue
    return IRB.CreateICmpSGE(LastAccessedByte, ShadowValue);
}

Instruction *AddressSanitizer::generateCrashCode(Instruction *InsertBefore,
                                                 Value *Addr, bool IsWrite,
                                                 size_t AccessSizeIndex,
                                                 Value *SizeArgument)
{
    IRBuilder<> IRB(InsertBefore);
    CallInst *Call = nullptr;
    if (SizeArgument)
    {
        Call = IRB.CreateCall(AsanErrorCallbackSized[IsWrite],
                              {Addr, SizeArgument});
    }
    else
    {
        Call = IRB.CreateCall(AsanErrorCallback[IsWrite][AccessSizeIndex], Addr);
    }
    Call->setCannotMerge();
    return Call;
}

static size_t TypeSizeToSizeIndex(uint32_t TypeSize)
{
    size_t Res = countTrailingZeros(TypeSize / 8);
    assert(Res < kNumberOfAccessSizes);
    return Res;
}

void AddressSanitizer::declareExternElrangeSymbol(Module &M)
{
    ExternSGXSanEnclaveBaseAddr = dyn_cast_or_null<GlobalVariable>(M.getOrInsertGlobal("g_enclave_base", IntptrTy));
    assert(ExternSGXSanEnclaveBaseAddr && "Failed to create extern uint64_t g_enclave_base");
    ExternSGXSanEnclaveBaseAddr->setLinkage(GlobalValue::ExternalLinkage);
    ExternSGXSanEnclaveSizeAddr = dyn_cast_or_null<GlobalVariable>(M.getOrInsertGlobal("g_enclave_size", IntptrTy));
    assert(ExternSGXSanEnclaveSizeAddr && "Failed to create extern uint64_t g_enclave_size");
    ExternSGXSanEnclaveSizeAddr->setLinkage(GlobalValue::ExternalLinkage);
}

void AddressSanitizer::instrumentAddress(Instruction *OrigIns, Instruction *InsertBefore, Value *Addr,
                                         uint32_t TypeSize, bool IsWrite, Value *SizeArgument, bool UseCalls)
{
    assert(TypeSize > 0 && TypeSize % 8 == 0);

    IRBuilder<> IRB(InsertBefore);
    Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
    size_t AccessSizeIndex = TypeSizeToSizeIndex(TypeSize);

    // <Use elrange guard page to detect cross boundary, below is c-like code>
    // step0:
    // cmp (start < EnclaveBase)
    // branch step3(or access, TBridge), step1;
    //
    // step1:
    // cmp (start > EnclaveEnd)
    // branch step3(or access, TBridge), step2;
    //
    // step2:
    // shadowbyte check; // now totally in elrange(, or trigger shadow map guard #PF before enclave guard #PF only if operation is not aligned)
    // branch access;
    //
    // <BEGIN: only not at TBridge>
    // step3:
    // cmp (end < EnclaveBase /* | start > EnclaveEnd */)
    // branch step4, access;
    //
    // step4:
    // Out-Enclave-Addr Whitelist Check; // now totally out elrange
    // branch access;
    // <END: only not at TBridge>
    //
    // access:
    BasicBlock *step0BB = nullptr, *step1BB = nullptr, *step2BB = nullptr,
               *step3BB = nullptr, *step4BB = nullptr, *accessBB = nullptr;
    step0BB = InsertBefore->getParent();
    accessBB = SplitBlock(step0BB, InsertBefore);
    if (isFuncAtEnclaveTBridge)
    {
        step2BB = BasicBlock::Create(*C, "step2_BB", step0BB->getParent(), accessBB);
    }
    else
    {
        step4BB = BasicBlock::Create(*C, "step4_BB", step0BB->getParent(), accessBB);
        step3BB = BasicBlock::Create(*C, "step3_BB", step0BB->getParent(), step4BB);
        step2BB = BasicBlock::Create(*C, "step2_BB", step0BB->getParent(), step3BB);
    }
    step1BB = BasicBlock::Create(*C, "step1_BB", step0BB->getParent(), step2BB);

    Instruction *step0BBTerm = step0BB->getTerminator();
    IRB.SetInsertPoint(step0BBTerm);
    Value *StartAddrULTEnclaveBase = IRB.CreateICmpULT(AddrLong, SGXSanEnclaveBase);
    IRB.CreateCondBr(StartAddrULTEnclaveBase, step3BB ? step3BB : accessBB, step1BB, MDBuilder(*C).createBranchWeights(1, 100000));
    step0BBTerm->eraseFromParent();

    IRB.SetInsertPoint(step1BB);
    Value *StartAddrUGTEnclaveEnd = IRB.CreateICmpUGE(AddrLong, SGXSanEnclaveEndPlus1);
    IRB.CreateCondBr(StartAddrUGTEnclaveEnd, step3BB ? step3BB : accessBB, step2BB, MDBuilder(*C).createBranchWeights(1, 100000));

    IRB.SetInsertPoint(step2BB);
    Instruction *ShadowCheckInsertPoint = IRB.CreateBr(accessBB);

    if (not isFuncAtEnclaveTBridge)
    {
        IRB.SetInsertPoint(step3BB);
        Value *EndAddrULTEnclaveBase = IRB.CreateICmpULT(
            IRB.CreateAdd(AddrLong, ConstantInt::get(IntptrTy, (TypeSize >> 3) - 1)),
            SGXSanEnclaveBase);
        IRB.CreateCondBr(EndAddrULTEnclaveBase, step4BB, accessBB, MDBuilder(*C).createBranchWeights(100000, 1));

        IRB.SetInsertPoint(step4BB);
        Instruction *WhitelistCheckInsertPoint = IRB.CreateBr(accessBB);

        IRB.SetInsertPoint(WhitelistCheckInsertPoint);
        IRB.CreateCall(WhitelistOfAddrOutEnclave_query_ex,
                       {IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()),
                        ConstantInt::get(IntptrTy, (TypeSize >> 3)),
                        IRB.getInt1(IsWrite),
                        IRB.getInt1(hasCmpUser(OrigIns)),
                        IRB.CreateGlobalStringPtr(OrigIns->getFunction()->getName())});
    }

    // start instrument shadowbyte check
    IRB.SetInsertPoint(ShadowCheckInsertPoint);
#if (USED_LOG_LEVEL >= 4 /* LOG_LEVEL_TRACE */)
    IRB.CreateCall(WhitelistOfAddrOutEnclave_add_in_enclave_access_cnt);
#endif
    if (UseCalls)
    {
        IRB.CreateCall(AsanMemoryAccessCallback[IsWrite][AccessSizeIndex],
                       AddrLong);
        return;
    }

    Type *ShadowTy = IntegerType::get(*C, std::max(8U, TypeSize >> Mapping.Scale));
    Type *ShadowPtrTy = PointerType::get(ShadowTy, 0);
    Value *ShadowPtr = memToShadow(AddrLong, IRB);
    Value *CmpVal = Constant::getNullValue(ShadowTy);
    Value *ShadowValue = IRB.CreateLoad(ShadowTy, IRB.CreateIntToPtr(ShadowPtr, ShadowPtrTy));

    // filte out sensitive poison value, then sensitive partial valid object oob access can be detected
    if (TypeSize == 128)
    {
        ShadowValue = IRB.CreateAnd(ShadowValue, IRB.getInt16(0x8F8F));
    }
    else if (!ClAlwaysSlowPath)
    {
        ShadowValue = IRB.CreateAnd(ShadowValue, IRB.getInt8(0x8F));
    }

    Value *Cmp = IRB.CreateICmpNE(ShadowValue, CmpVal);
    size_t Granularity = 1ULL << Mapping.Scale;

    BasicBlock *SlowPathBB = nullptr;
    if (ClAlwaysSlowPath || (TypeSize < 8 * Granularity))
    {
        // We use branch weights for the slow path check, to indicate that the slow
        // path is rarely taken. This seems to be the case for SPEC benchmarks.
        // here we know ShadowCheckInsertPoint must be a BranchInst
        SlowPathBB = BasicBlock::Create(*C, "slow_path", step2BB->getParent(), step2BB->getNextNode());
        IRB.CreateCondBr(Cmp, SlowPathBB, accessBB, MDBuilder(*C).createBranchWeights(1, 100000));

        IRB.SetInsertPoint(SlowPathBB);
        Cmp = createSlowPathCmp(IRB, AddrLong, ShadowValue, TypeSize);
    }

    BasicBlock *CrashBlock = BasicBlock::Create(*C, "crash", accessBB->getParent(), (SlowPathBB ? SlowPathBB : step2BB)->getNextNode());
    IRB.CreateCondBr(Cmp, CrashBlock, accessBB, MDBuilder(*C).createBranchWeights(1, 100000));
    ShadowCheckInsertPoint->eraseFromParent();

    IRB.SetInsertPoint(CrashBlock);
    Instruction *CrashTerm = IRB.CreateUnreachable();
    // Load/Store instrumentations almost finish here

    // Crash code
    Instruction *Crash = generateCrashCode(CrashTerm, AddrLong, IsWrite, AccessSizeIndex, SizeArgument);
    Crash->setDebugLoc(OrigIns->getDebugLoc());
}

// Instrument unusual size or unusual alignment.
// We can not do it with a single check, so we do 1-byte check for the first
// and the last bytes. We call __asan_report_*_n(addr, real_size) to be able
// to report the actual access size.
void AddressSanitizer::instrumentUnusualSizeOrAlignment(
    Instruction *I, Instruction *InsertBefore, Value *Addr, uint32_t TypeSize,
    bool IsWrite, Value *SizeArgument, bool UseCalls)
{
    IRBuilder<> IRB(InsertBefore);
    // what about the remained bits?
    Value *Size = ConstantInt::get(IntptrTy, TypeSize / 8);
    Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
    if (UseCalls)
    {
        if (IsWrite)
            IRB.CreateCall(AsanMemoryAccessCallbackSizedStore, {AddrLong, Size});
        else
            IRB.CreateCall(AsanMemoryAccessCallbackSizedLoad, {AddrLong, Size,
                                                               IRB.getInt1(hasCmpUser(I)),
                                                               IRB.CreateGlobalStringPtr(I->getFunction()->getName())});
    }
    else
    {
        Value *LastByte = IRB.CreateIntToPtr(
            IRB.CreateAdd(AddrLong, ConstantInt::get(IntptrTy, TypeSize / 8 - 1)),
            Addr->getType());
        instrumentAddress(I, InsertBefore, Addr, 8, IsWrite, Size, false);
        instrumentAddress(I, InsertBefore, LastByte, 8, IsWrite, Size, false);
    }
}

static void doInstrumentAddress(AddressSanitizer *Pass, Instruction *I,
                                Instruction *InsertBefore, Value *Addr,
                                MaybeAlign Alignment, unsigned Granularity,
                                uint32_t TypeSize, bool IsWrite,
                                Value *SizeArgument, bool UseCalls)
{
    // Instrument a 1-, 2-, 4-, 8-, or 16- byte access with one check
    // if the data is properly aligned.
    if ((TypeSize == 8 || TypeSize == 16 || TypeSize == 32 || TypeSize == 64 ||
         TypeSize == 128) &&
        (!Alignment || *Alignment >= Granularity || *Alignment >= TypeSize / 8))
        return Pass->instrumentAddress(I, InsertBefore, Addr, TypeSize, IsWrite, nullptr, UseCalls);
    Pass->instrumentUnusualSizeOrAlignment(I, InsertBefore, Addr, TypeSize,
                                           IsWrite, nullptr, UseCalls);
}

void AddressSanitizer::instrumentMop(InterestingMemoryOperand &O, bool UseCalls)
{
    Value *Addr = O.getPtr();

    if (O.IsWrite)
        NumInstrumentedWrites++;
    else
        NumInstrumentedReads++;

    unsigned Granularity = 1 << Mapping.Scale;

    doInstrumentAddress(this, O.getInsn(), O.getInsn(), Addr, O.Alignment,
                        Granularity, O.TypeSize, O.IsWrite, nullptr, UseCalls);
}

// Instrument memset/memmove/memcpy
void AddressSanitizer::instrumentMemIntrinsic(MemIntrinsic *MI)
{
    IRBuilder<> IRB(MI);
    if (isa<MemTransferInst>(MI))
    {
        IRB.CreateCall(
            isa<MemMoveInst>(MI) ? AsanMemmove : AsanMemcpy,
            {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
             IRB.CreatePointerCast(MI->getOperand(1), IRB.getInt8PtrTy()),
             IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
    }
    else if (isa<MemSetInst>(MI))
    {
        IRB.CreateCall(
            AsanMemset,
            {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
             IRB.CreateIntCast(MI->getOperand(1), IRB.getInt32Ty(), false),
             IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
    }
    MI->eraseFromParent();
}

// Instrument memset_s/memmove_s/memcpy_s
void AddressSanitizer::instrumentSecMemIntrinsic(CallInst *CI)
{
    StringRef callee_name = getDirectCalleeName(CI);
    IRBuilder<> IRB(CI);
    CallInst *tempCI = nullptr;
    if (callee_name == "memcpy_s")
    {
        tempCI = IRB.CreateCall(SGXSanMemcpyS, {CI->getOperand(0), CI->getOperand(1),
                                                CI->getOperand(2), CI->getOperand(3)});
    }
    else if (callee_name == "memset_s")
    {
        tempCI = IRB.CreateCall(SGXSanMemsetS, {CI->getOperand(0), CI->getOperand(1),
                                                CI->getOperand(2), CI->getOperand(3)});
    }
    else if (callee_name == "memmove_s")
    {
        tempCI = IRB.CreateCall(SGXSanMemmoveS, {CI->getOperand(0), CI->getOperand(1),
                                                 CI->getOperand(2), CI->getOperand(3)});
    }
    else
        abort();
    CI->replaceAllUsesWith(tempCI);
    CI->eraseFromParent();
}

#if (USE_SGXSAN_MALLOC)
// Instrument malloc/free/calloc/realloc
void AddressSanitizer::instrumentHeapCall(CallInst *CI)
{
    StringRef callee_name = getDirectCalleeName(CI);
    IRBuilder<> IRB(CI);
    CallInst *tempCI = nullptr;
    if (callee_name == "malloc")
    {
        tempCI = IRB.CreateCall(SGXSanMalloc, CI->getOperand(0));
    }
    else if (callee_name == "free")
    {
        tempCI = IRB.CreateCall(SGXSanFree, CI->getOperand(0));
    }
    else if (callee_name == "calloc")
    {
        tempCI = IRB.CreateCall(SGXSanCalloc, {CI->getOperand(0), CI->getOperand(1)});
    }
    else if (callee_name == "realloc")
    {
        tempCI = IRB.CreateCall(SGXSanRealloc, {CI->getOperand(0), CI->getOperand(1)});
    }
    else
        abort();
    CI->replaceAllUsesWith(tempCI);
    CI->eraseFromParent();
}
#endif

void AddressSanitizer::instrumentGlobalPropageteWhitelist(StoreInst *SI)
{
    IRBuilder<> IRB(SI);
    Value *val = SI->getValueOperand();

    IRB.CreateCall(WhitelistOfAddrOutEnclave_global_propagate, {val->getType()->isPointerTy()
                                                                    ? IRB.CreatePointerCast(val, IRB.getInt8PtrTy())
                                                                    : IRB.CreateIntToPtr(val, IRB.getInt8PtrTy())});
}

Type *AddressSanitizer::unpackArrayType(Type *type)
{
    Type *elementType = nullptr;
    if (type->isPointerTy())
    {
        elementType = type->getPointerElementType();
    }
    else if (type->isArrayTy())
    {
        elementType = type->getArrayElementType();
    }
    else
    {
        return type;
    }
    while (elementType->isArrayTy())
    {
        elementType = elementType->getArrayElementType();
    }
    return elementType;
}

#define FOR_LOOP_BEG(insert_point, count)                                       \
    Instruction *forBodyTerm = SplitBlockAndInsertIfThen(                       \
        IRB.CreateICmpSGT(count, IRB.getInt32(0), ""),                          \
        insert_point,                                                           \
        false);                                                                 \
    IRB.SetInsertPoint(forBodyTerm);                                            \
    PHINode *phi = IRB.CreatePHI(IRB.getInt32Ty(), 2, "");                      \
    phi->addIncoming(IRB.getInt32(0), forBodyTerm->getParent()->getPrevNode()); \
    BasicBlock *forBodyEntry = phi->getParent();

#define FOR_LOOP_END(count)                                                                             \
    /*  instrumentParameterCheck may insert new bb, so forBodyTerm may not belong to forBodyEntry BB */ \
    IRB.SetInsertPoint(forBodyTerm);                                                                    \
    Value *inc = IRB.CreateAdd(phi, IRB.getInt32(1), "", true, true);                                   \
    phi->addIncoming(inc, forBodyTerm->getParent());                                                    \
    ReplaceInstWithInst(forBodyTerm, BranchInst::Create(                                                \
                                         forBodyEntry,                                                  \
                                         forBodyTerm->getParent()->getNextNode(),                       \
                                         IRB.CreateICmpSLT(inc, count)));

// Must already set insert point properly in IRB
bool AddressSanitizer::instrumentParameterCheck(Value *operand, IRBuilder<> &IRB, const DataLayout &DL,
                                                int depth, Value *eleCnt, Value *operandAddr,
                                                bool checkCurrentLevelPtr)
{
    if (depth++ > 10)
        return false;

    Type *operandType = operand->getType();
    // fix-me: how about FunctionType
    if (PointerType *pointerType = dyn_cast<PointerType>(operandType))
    {
        if (!pointerType->getElementType()->isSized())
            return false; // ignore unsized, e.g. function pointer
        auto _eleSize = DL.getTypeAllocSize(pointerType->getElementType());
        if (_eleSize <= 0)
            return false;
        auto operandInt8ptr = IRB.CreatePointerCast(operand, IRB.getInt8PtrTy());
        auto eleSize = IRB.getInt64(_eleSize);
        if (eleCnt == nullptr)
            eleCnt = IRB.getInt32(-1);
        CallInst *isReadable = IRB.CreateCall(is_pointer_readable, {operandInt8ptr, eleSize, eleCnt});
        Instruction *PointerCheckTerm = SplitBlockAndInsertIfThen(isReadable, &(*IRB.GetInsertPoint()), false);
        IRB.SetInsertPoint(PointerCheckTerm);

        // now pointer is loadable
        if (checkCurrentLevelPtr)
            IRB.CreateCall(sgxsan_edge_check, {operandInt8ptr, eleSize, eleCnt});

        if (eleCnt == IRB.getInt32(0))
            abort();
        else if (eleCnt != IRB.getInt32(-1) && eleCnt != IRB.getInt32(1))
        {
            // multi element
            FOR_LOOP_BEG(PointerCheckTerm, eleCnt)
            Value *eleAddr = IRB.CreateGEP(operand, phi);
            auto ele = IRB.CreateLoad(eleAddr);
            /* if element is pointer then nullptr means no idea about element's sub-element count */
            instrumentParameterCheck(ele, IRB, DL, depth, nullptr, eleAddr);
            FOR_LOOP_END(eleCnt)
        }
        else
        {
            // one element
            auto ele = IRB.CreateLoad(operand);
            bool result = instrumentParameterCheck(ele, IRB, DL, depth, nullptr, operand);
            if (not result)
                ele->eraseFromParent();
        }

        return true;
    }
    else if (StructType *structType = dyn_cast<StructType>(operandType))
    {
        Instruction *insertPoint = &(*IRB.GetInsertPoint());
        bool has_modified = false;
        // struct type cannot GEP with phi, since elements of struct may be different from each other
        for (size_t index = 0; index < structType->elements().size(); index++)
        {
            IRB.SetInsertPoint(insertPoint);
            Value *element = IRB.CreateExtractValue(operand, index);
            bool result = instrumentParameterCheck(element, IRB, DL, depth);
            if (result)
                has_modified = true;
            else
            {
                if (auto I = dyn_cast<Instruction>(element))
                    I->eraseFromParent();
            }
        }
        return has_modified;
    }
    else if (ArrayType *arrayType = dyn_cast<ArrayType>(operandType))
    {
        Type *unpackedType = unpackArrayType(arrayType);
        if (!unpackedType->isPointerTy() && !unpackedType->isStructTy())
            // do not need instrument
            return false;
        Instruction *insertPoint = &(*IRB.GetInsertPoint());
        bool has_modified = false;
        if (operandAddr)
        {
            // lvalue case, that has memobj
            auto cnt = IRB.getInt32(arrayType->getNumElements());
            FOR_LOOP_BEG(insertPoint, cnt)
            Value *eleAddr = IRB.CreateGEP(operandAddr, {IRB.getInt32(0), phi});
            auto ele = IRB.CreateLoad(eleAddr);
            instrumentParameterCheck(ele, IRB, DL, depth, nullptr, eleAddr);
            FOR_LOOP_END(cnt)
            has_modified = true;
        }
        else
        {
            // rvalue case, that only in register
            for (uint64_t index = 0; index < arrayType->getNumElements(); index++)
            {
                IRB.SetInsertPoint(insertPoint);
                Value *element = IRB.CreateExtractValue(operand, index);
                bool result = instrumentParameterCheck(element, IRB, DL, depth);
                if (result)
                    has_modified = true;
                else
                {
                    if (auto I = dyn_cast<Instruction>(element))
                        I->eraseFromParent();
                }
            }
        }
        return has_modified;
    }
    return false;
}

// instrument `EnclaveTLSConstructorAtTBridgeBegin` and `EnclaveTLSDestructorAtTBridgeEnd` at ecallWrapper function begin and end respectively
void AddressSanitizer::__instrumentTLSMgr(Function *ecallWrapper)
{
    assert(ecallWrapper);
    if (TLSMgrInstrumentedEcall.count(ecallWrapper) == 0)
    {
        auto &firstFuncInsertPoint = ecallWrapper->front().front();
        IRBuilder<> IRB(&firstFuncInsertPoint);
        IRB.CreateCall(EnclaveTLSConstructorAtTBridgeBegin);

        for (auto RetInst : SGXSanInstVisitor::visitFunction(*ecallWrapper).BroadReturnInstVec)
        {
            IRB.SetInsertPoint(RetInst);
            IRB.CreateCall(EnclaveTLSDestructorAtTBridgeEnd);
        }
        TLSMgrInstrumentedEcall.emplace(ecallWrapper);
    }
}

bool AddressSanitizer::instrumentRealEcall(CallInst *CI)
{
    if (CI == nullptr)
        return false;

    __instrumentTLSMgr(CI->getFunction());

    IRBuilder<> IRB(CI);
    const DataLayout &DL = CI->getModule()->getDataLayout();
    // instrument `sgxsan_edge_check` for each actual parameter of RealEcall before RealEcall
    for (unsigned int i = 0; i < (CI->getNumOperands() - 1); i++)
    {
        IRB.SetInsertPoint(CI);
        Value *operand = CI->getOperand(i);
        // fix-me: currently find array is also passed as pointer
        if (isa<PointerType>(operand->getType()))
        {
            // Instruction *PointerCheckTerm = SplitBlockAndInsertIfThen(IRB.CreateNot(IRB.CreateIsNull(operand)), CI, false);
            // maybe operand is a (array-)pointer and it has more then 1 element accroding to EDL Sementics
            auto lenAndValue = getLenAndValueByParamInEDL(CI->getFunction(), operand);
            Value *ptrEleCnt = convertPointerLenAndValue2CountValue(operand, CI, lenAndValue);
            // if it is [in]/[out] (array-)pointer, sub-element still need to be filled into whitelist
            instrumentParameterCheck(operand, IRB, DL, 0, ptrEleCnt, nullptr,
                                     lenAndValue.second == nullptr /* _in_ prefixed ptr, needn't check */);
        }
        else if (ArrayType *arrType = dyn_cast<ArrayType>(operand->getType()))
        {
            // seems never trigger(hopefully)
            assert(false);
            Value *tempOp = operand;
            while (isa<CastInst>(tempOp))
            {
                tempOp = cast<CastInst>(tempOp)->getOperand(0);
            }
            if (Instruction *I = dyn_cast<Instruction>(tempOp))
            {
                Value *addr = I->getOperand(0);
                assert(addr->getType()->getPointerElementType() == arrType);
                instrumentParameterCheck(addr, IRB, DL, 0, IRB.getInt32(1), nullptr, false);
            }
            else
            {
                instrumentParameterCheck(operand, IRB, DL, 0);
            }
        }
        else
        {
            instrumentParameterCheck(operand, IRB, DL, 0);
        }
    }
    // instrument `WhitelistOfAddrOutEnclave_active` before RealEcall
    IRB.SetInsertPoint(CI);
    IRB.CreateCall(WhitelistOfAddrOutEnclave_active);
    // instrument `WhitelistOfAddrOutEnclave_deactive` after RealEcall
    IRB.SetInsertPoint(CI->getNextNode());
    IRB.CreateCall(WhitelistOfAddrOutEnclave_deactive);

    return true;
}

bool AddressSanitizer::instrumentOcallWrapper(Function &OcallWrapper)
{
    IRBuilder<> IRB(&OcallWrapper.front().front());
    IRB.CreateCall(WhitelistOfAddrOutEnclave_deactive);

    for (auto RetInst : SGXSanInstVisitor::visitFunction(OcallWrapper).BroadReturnInstVec)
    {
        const DataLayout &DL = RetInst->getModule()->getDataLayout();
        for (Argument &arg : OcallWrapper.args())
        {
            // treat ocall-wrapper argument as _in_ prefixed parameter in real-ecall
            IRB.SetInsertPoint(RetInst);
            Type *argType = arg.getType();
            if (argType->isPointerTy())
            {
                std::string argName = SGXSanGetName(&arg).str();
                Value *ptrEleCnt = nullptr;
                if (argName != "")
                {
                    // make sure parameter is passed in enclave
                    // '__tmp_xxx' exist, then means there is routine that use xxx at untrusted side, and copy xxx back to trusted side
                    // fix-me: implementation is tricky
                    if (getValueByStrInFunction(&OcallWrapper, isValueNameEqualWith, "__tmp_" + argName) == nullptr)
                        continue;

                    auto lenAndValue = getLenAndValueByNameInEDL(RetInst->getFunction(), "_len_" + argName);
                    ptrEleCnt = convertPointerLenAndValue2CountValue(&arg, RetInst, lenAndValue);
                }
                instrumentParameterCheck(&arg, IRB, DL, 0, ptrEleCnt, nullptr, false);
            }
            // it seem func arg will never be an array or a struct
            else
            {
                instrumentParameterCheck(&arg, IRB, DL, 0);
            }
        }
        IRB.SetInsertPoint(RetInst);
        IRB.CreateCall(WhitelistOfAddrOutEnclave_active);
    }
    return true;
}

bool AddressSanitizer::instrumentFunction(Function &F)
{
    // dbgs() << "[SGXSan] Processing " << F.getName() << " ...\n";
    isFuncAtEnclaveTBridge = false;
    if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage)
        return false;
    if (F.getName().startswith("__asan_"))
        return false;
    bool FunctionModified = false;

    LLVM_DEBUG(dbgs() << "ASAN instrumenting:\n"
                      << F << "\n");
    initializeCallbacks(*F.getParent());

    // We want to instrument every address only once per basic block (unless there
    // are calls between uses).
    SmallVector<InterestingMemoryOperand, 16> OperandsToInstrument;
    SmallVector<MemIntrinsic *, 16> IntrinToInstrument;
    SmallVector<Instruction *, 8> NoReturnCalls;
    SmallVector<BasicBlock *, 16> AllBlocks;
    SmallVector<StoreInst *, 16> GlobalVariableStoreInsts;
    SmallVector<CallInst *, 16> SecIntrinToInstrument;
#if (USE_SGXSAN_MALLOC)
    SmallVector<CallInst *, 16> HeapCIToInstrument;
#endif
    // there may be several `tail call` RealEcall when compiling with `-O2` flag
    SmallVector<CallInst *, 16> RealEcallInsts;
    SmallVector<CallInst *, 16> SGXOcallInsts;
    int NumAllocas = 0;

    // Fill the set of memory operations to instrument.
    for (auto &BB : F)
    {
        AllBlocks.push_back(&BB);
        int NumInsnsPerBB = 0;
        for (auto &Inst : BB)
        {
            SmallVector<InterestingMemoryOperand, 1> InterestingOperands;
            getInterestingMemoryOperands(&Inst, InterestingOperands, GlobalVariableStoreInsts);

            if (!InterestingOperands.empty())
            {
                for (auto &Operand : InterestingOperands)
                {
                    OperandsToInstrument.push_back(Operand);
                    NumInsnsPerBB++;
                }
            }
            else if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(&Inst))
            {
                if (!MI->hasMetadata("nosanitize"))
                {
                    // ok, take it.
                    IntrinToInstrument.push_back(MI);
                    NumInsnsPerBB++;
                }
            }
            else
            {
                if (isa<AllocaInst>(Inst))
                    NumAllocas++;
                // if (auto *CB = dyn_cast<CallBase>(&Inst))
                // {
                //     // A call inside BB.
                //     if (CB->doesNotReturn() && !CB->hasMetadata("nosanitize"))
                //         NoReturnCalls.push_back(CB);
                // }
            }
            if (CallInst *CI = dyn_cast<CallInst>(&Inst))
            {
                StringRef callee_name = getDirectCalleeName(CI);
                if (F.getName() == ("sgx_" /* ecall wrapper prefix */ + callee_name.str()))
                {
                    // it's an ecall wrapper
                    RealEcallInsts.push_back(CI);
                    isFuncAtEnclaveTBridge = true;
                }
                else if (callee_name == "sgx_ocall")
                {
                    SGXOcallInsts.push_back(CI);
                    isFuncAtEnclaveTBridge = true;
                }
                else if (callee_name == "memcpy_s" || callee_name == "memset_s" || callee_name == "memmove_s")
                {
                    SecIntrinToInstrument.push_back(CI);
                }
#if (USE_SGXSAN_MALLOC)
                else if (callee_name == "malloc" || callee_name == "free" || callee_name == "calloc" || callee_name == "realloc")
                {
                    HeapCIToInstrument.push_back(CI);
                }
#endif
            }

            if (NumInsnsPerBB >= ClMaxInsnsToInstrumentPerBB)
                break;
        }
    }
    bool UseCalls = (ClInstrumentationWithCallsThreshold >= 0 &&
                     OperandsToInstrument.size() + IntrinToInstrument.size() >
                         (unsigned)ClInstrumentationWithCallsThreshold);

    // Instrument.

    // sgxsdk should ensure SGXSanEnclaveSize > 0 and SGXSanEnclaveEnd do not overflow
    IRBuilder<> IRB(&F.front().front());
    SGXSanEnclaveBase = IRB.CreateLoad(IntptrTy, ExternSGXSanEnclaveBaseAddr, "enclave_base");
    SGXSanEnclaveEndPlus1 = IRB.CreateAdd(SGXSanEnclaveBase, IRB.CreateLoad(IntptrTy, ExternSGXSanEnclaveSizeAddr, "enclave_size"), "enclave_end_plus1");

    for (auto &Operand : OperandsToInstrument)
    {
        instrumentMop(Operand, UseCalls);
        FunctionModified = true;
    }
    for (auto Inst : IntrinToInstrument)
    {
        instrumentMemIntrinsic(Inst);
        FunctionModified = true;
    }
    for (auto CI : SecIntrinToInstrument)
    {
        instrumentSecMemIntrinsic(CI);
        FunctionModified = true;
    }
#if (USE_SGXSAN_MALLOC)
    for (auto CI : HeapCIToInstrument)
    {
        instrumentHeapCall(CI);
        FunctionModified = true;
    }
#endif
    if (!isFuncAtEnclaveTBridge)
    {
        for (auto Inst : GlobalVariableStoreInsts)
        {
            instrumentGlobalPropageteWhitelist(Inst);
            FunctionModified = true;
        }
    }

    FunctionStackPoisoner FSP(F, *this);
    bool ChangedStack = FSP.runOnFunction();

    for (auto RealEcallInst : RealEcallInsts)
    {
        // when it is an ecall wrapper
        instrumentRealEcall(RealEcallInst);
        FunctionModified = true;
    }

    if (SGXOcallInsts.size() > 0)
    {
        instrumentOcallWrapper(F);
        FunctionModified = true;
    }

    // We must unpoison the stack before NoReturn calls (throw, _exit, etc).
    // See e.g. https://github.com/google/sanitizers/issues/37
    // for (auto CI : NoReturnCalls)
    // {
    //     IRBuilder<> IRB(CI);
    //     IRB.CreateCall(AsanHandleNoReturnFunc, {});
    // }

    // if (ChangedStack || !NoReturnCalls.empty())
    if (ChangedStack)
        FunctionModified = true;

    LLVM_DEBUG(dbgs() << "ASAN done instrumenting: " << FunctionModified << " "
                      << F << "\n");

    return FunctionModified;
}

uint64_t AddressSanitizer::getAllocaSizeInBytes(const AllocaInst &AI) const
{
    uint64_t ArraySize = 1;
    if (AI.isArrayAllocation())
    {
        const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
        assert(CI && "non-constant array size");
        ArraySize = CI->getZExtValue();
    }
    Type *Ty = AI.getAllocatedType();
    uint64_t SizeInBytes =
        AI.getModule()->getDataLayout().getTypeAllocSize(Ty);
    return SizeInBytes * ArraySize;
}

/// Check if we want (and can) handle this alloca.
bool AddressSanitizer::isInterestingAlloca(const AllocaInst &AI)
{
    auto PreviouslySeenAllocaInfo = ProcessedAllocas.find(&AI);

    if (PreviouslySeenAllocaInfo != ProcessedAllocas.end())
        return PreviouslySeenAllocaInfo->getSecond();

    bool IsInteresting =
        (AI.getAllocatedType()->isSized() &&
         // alloca() may be called with 0 size, ignore it.
         ((!AI.isStaticAlloca()) || getAllocaSizeInBytes(AI) > 0) &&
         // We are only interested in allocas not promotable to registers.
         // Promotable allocas are common under -O0.
         (!ClSkipPromotableAllocas || !isAllocaPromotable(&AI)) &&
         // inalloca allocas are not treated as static, and we don't want
         // dynamic alloca instrumentation for them as well.
         !AI.isUsedWithInAlloca() &&
         // swifterror allocas are register promoted by ISel
         !AI.isSwiftError());

    ProcessedAllocas[&AI] = IsInteresting;
    return IsInteresting;
}

bool AddressSanitizer::ignoreAccess(Value *Ptr)
{
    // Do not instrument acesses from different address spaces; we cannot deal
    // with them.
    Type *PtrTy = cast<PointerType>(Ptr->getType()->getScalarType());
    if (PtrTy->getPointerAddressSpace() != 0)
        return true;

    // Ignore swifterror addresses.
    // swifterror memory addresses are mem2reg promoted by instruction
    // selection. As such they cannot have regular uses like an instrumentation
    // function and it makes no sense to track them as memory.
    if (Ptr->isSwiftError())
        return true;

    // Treat memory accesses to promotable allocas as non-interesting since they
    // will not cause memory violations. This greatly speeds up the instrumented
    // executable at -O0.
    if (auto AI = dyn_cast_or_null<AllocaInst>(Ptr))
        if (ClSkipPromotableAllocas && !isInterestingAlloca(*AI))
            return true;

    return false;
}
