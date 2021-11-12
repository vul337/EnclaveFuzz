#include "AddressSanitizer.hpp"
#include "FunctionStackPoisoner.hpp"
#include "SGXSanManifest.h"
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

static cl::opt<bool> ClCheckAddrOverflow(
    "sgxsan-check-addr-overflow",
    cl::desc("Whether check address overflow, default value is false, as in detection work, we can use 0-address unmap to find problem"),
    cl::Hidden,
    cl::init(false));

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");

static ShadowMapping getShadowMapping()
{
    ShadowMapping Mapping;
    Mapping.Scale = 3;
    Mapping.Offset = SGXSAN_SHADOW_MAP_BASE;
    return Mapping;
}

AddressSanitizer::AddressSanitizer(Module &M)
{
    C = &(M.getContext());
    LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    Mapping = getShadowMapping();
}

// 构建一个ShadowMemory
// 写函数Pass，捕捉所有访存操作(Load/Store/内存操作库函数)并插桩代码检查对应的ShadowByte。具体被调用的检查代码在Runtime中实现。
// 函数Pass中捕捉栈变量，将栈变量调整到函数开头，预先安插好所有的Redzone（栈变量），并进行Poison；函数返回前，将Redzone Unpoison。
// 关于堆变量。在Runtime中需要Wrap一下Malloc/Free（Malloc时额外多分配Redzone），并对Redzone进行Poison/Unpoison。
// 关于全局变量，模块Pass先提取好之前处理顶级声明时准备好的全局变量信息表。然后遍历全局变量，修改它以插入Redzone。将全局变量信息传给Runtime，让Runtime污染Redzone。

void AddressSanitizer::initializeCallbacks(Module &M)
{
    IRBuilder<> IRB(*C);
    // Create __asan_report* callbacks.
    // IsWrite and TypeSize are encoded in the function name.

    for (size_t AccessIsWrite = 0; AccessIsWrite <= 1; AccessIsWrite++)
    {
        const std::string TypeStr = AccessIsWrite ? "store" : "load";

        SmallVector<Type *, 3> Args2 = {IntptrTy, IntptrTy};
        SmallVector<Type *, 2> Args1{1, IntptrTy};

        AsanErrorCallbackSized[AccessIsWrite] = M.getOrInsertFunction(
            kAsanReportErrorTemplate + TypeStr + "_n",
            FunctionType::get(IRB.getVoidTy(), Args2, false));
        AsanMemoryAccessCallbackSized[AccessIsWrite] = M.getOrInsertFunction(
            ClMemoryAccessCallbackPrefix + TypeStr + "N",
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
}

void AddressSanitizer::getInterestingMemoryOperands(
    Instruction *I, SmallVectorImpl<InterestingMemoryOperand> &Interesting)
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
        auto *F = CI->getCalledFunction();
        if (F && (F->getName().startswith("llvm.masked.load.") ||
                  F->getName().startswith("llvm.masked.store.")))
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
    Value *SGXSanEnclaveBase = IRB.CreateLoad(IntptrTy, ExternSGXSanEnclaveBaseAddr);
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

    IRBuilder<> IRB(InsertBefore);
    Value *AddrLong = IRB.CreatePointerCast(Addr, IntptrTy);
    size_t AccessSizeIndex = TypeSizeToSizeIndex(TypeSize);

    // check elrange
    assert(TypeSize > 0 && TypeSize % 8 == 0);
    Value *EndAddrLong = IRB.CreateAdd(AddrLong, ConstantInt::get(IntptrTy, (TypeSize >> 3) - 1));

    if (ClCheckAddrOverflow)
    {
        // if (start > end) //when start == end, only visit one byte
        // {
        //     crash; // unreachable                <= IntegerOverFlowTerm
        // }
        // continue check;                          <= InsertBefore
        // (this check maybe unnecessarily, this could tested by kernel 0 addr SIGSEG)
        Value *CmpStartAddrUGTEndAddr = IRB.CreateICmpUGT(AddrLong, EndAddrLong);
        Instruction *IntegerOverFlowTerm = SplitBlockAndInsertIfThen(CmpStartAddrUGTEndAddr, InsertBefore, true);
        Instruction *RangeCrash = generateCrashCode(IntegerOverFlowTerm, AddrLong, IsWrite, AccessSizeIndex, SizeArgument);
        RangeCrash->setDebugLoc(OrigIns->getDebugLoc());

        // update insert point
        IRB.SetInsertPoint(InsertBefore);
    }
    // now start <= end
    // sgxsdk should ensure SGXSanEnclaveSize > 0 and SGXSanEnclaveEnd do not overflow
    Value *SGXSanEnclaveBase = IRB.CreateLoad(IntptrTy, ExternSGXSanEnclaveBaseAddr);
    Value *SGXSanEnclaveSize = IRB.CreateLoad(IntptrTy, ExternSGXSanEnclaveSizeAddr);
    Value *SGXSanEnclaveEnd = IRB.CreateAdd(SGXSanEnclaveBase,
                                            IRB.CreateSub(SGXSanEnclaveSize, ConstantInt::get(IntptrTy, 1)));

    // if (not(end < EnclaveBase or start > EnclaveEnd)) // equal to if (end >= EnclaveBase and start <= EnclaveEnd))
    // {
    //     if (not(start >= EnclaveBase and end <= EnclaveEnd)) // equal to if (start < EnclaveBase or end > EnclaveEnd)
    //     {
    //         cross-boundary; // unreachable                                                       <= CrossBoundaryTerm
    //     }
    //     shadowbyte check; // so (start >= EnclaveBase and end <= EnclaveEnd)
    //                                                                                              <= NotTotallyOutEnclaveTerm
    // }
    // totally outside enclave (end < EnclaveBase or start > EnclaveEnd), needn't check             <= InsertBefore
    Value *CmpEndAddrUGEEnclaveBase = IRB.CreateICmpUGE(EndAddrLong, SGXSanEnclaveBase);
    Value *CmpStartAddrULEEnclaveEnd = IRB.CreateICmpULE(AddrLong, SGXSanEnclaveEnd);
    Instruction *NotTotallyOutEnclaveTerm = SplitBlockAndInsertIfThen(
        IRB.CreateAnd(CmpEndAddrUGEEnclaveBase, CmpStartAddrULEEnclaveEnd), InsertBefore, false);

    // second-step check
    IRB.SetInsertPoint(NotTotallyOutEnclaveTerm);
    Value *CmpStartAddrULTEnclaveBase = IRB.CreateICmpULT(AddrLong, SGXSanEnclaveBase);
    Value *CmpEndAddrUGTEnclaveEnd = IRB.CreateICmpUGT(EndAddrLong, SGXSanEnclaveEnd);
    Instruction *CrossBoundaryTerm = SplitBlockAndInsertIfThen(
        IRB.CreateOr(CmpStartAddrULTEnclaveBase, CmpEndAddrUGTEnclaveEnd), NotTotallyOutEnclaveTerm, true);
    Instruction *CrossBoundaryCrash = generateCrashCode(CrossBoundaryTerm, AddrLong, IsWrite, AccessSizeIndex, SizeArgument);
    CrossBoundaryCrash->setDebugLoc(OrigIns->getDebugLoc());

    // start instrument shadowbyte check
    IRB.SetInsertPoint(NotTotallyOutEnclaveTerm);
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

    Value *Cmp = IRB.CreateICmpNE(ShadowValue, CmpVal);
    Instruction *CrashTerm = nullptr;

    // We use branch weights for the slow path check, to indicate that the slow
    // path is rarely taken. This seems to be the case for SPEC benchmarks.
    // fixme: avoid extra branch
    Instruction *CheckTerm = SplitBlockAndInsertIfThen(
        Cmp, NotTotallyOutEnclaveTerm, false, MDBuilder(*C).createBranchWeights(1, 100000));
    assert(cast<BranchInst>(CheckTerm)->isUnconditional());
    BasicBlock *NextBB = CheckTerm->getSuccessor(0);
    IRB.SetInsertPoint(CheckTerm);
    Value *Cmp2 = createSlowPathCmp(IRB, AddrLong, ShadowValue, TypeSize);

    BasicBlock *CrashBlock =
        BasicBlock::Create(*C, "", NextBB->getParent(), NextBB);
    CrashTerm = new UnreachableInst(*C, CrashBlock);
    BranchInst *NewTerm = BranchInst::Create(CrashBlock, NextBB, Cmp2);
    ReplaceInstWithInst(CheckTerm, NewTerm);
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
        IRB.CreateCall(AsanMemoryAccessCallbackSized[IsWrite],
                       {AddrLong, Size});
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

bool AddressSanitizer::instrumentFunction(Function &F)
{
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
    int NumAllocas = 0;

    // Fill the set of memory operations to instrument.
    for (auto &BB : F)
    {
        AllBlocks.push_back(&BB);
        int NumInsnsPerBB = 0;
        for (auto &Inst : BB)
        {
            SmallVector<InterestingMemoryOperand, 1> InterestingOperands;
            getInterestingMemoryOperands(&Inst, InterestingOperands);

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
                // ok, take it.
                IntrinToInstrument.push_back(MI);
                NumInsnsPerBB++;
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
            if (NumInsnsPerBB >= ClMaxInsnsToInstrumentPerBB)
                break;
        }
    }
    bool UseCalls = (ClInstrumentationWithCallsThreshold >= 0 &&
                     OperandsToInstrument.size() + IntrinToInstrument.size() >
                         (unsigned)ClInstrumentationWithCallsThreshold);
    // Instrument.
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

    FunctionStackPoisoner FSP(F, *this);
    bool ChangedStack = FSP.runOnFunction();

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