#include "FunctionStackPoisoner.hpp"

using namespace llvm;

static const size_t kMinStackMallocSize = 1 << 6;  // 64B
static const size_t kMaxStackMallocSize = 1 << 16; // 64K
static const uintptr_t kCurrentStackFrameMagic = 0x41B58AB3;
static const uintptr_t kRetiredStackFrameMagic = 0x45E0360E;

// const char kAsanStackMallocNameTemplate[] = "__asan_stack_malloc_";
// const char kAsanStackFreeNameTemplate[] = "__asan_stack_free_";
const char kAsanGenPrefix[] = "___asan_gen_";
const char kAsanSetShadowPrefix[] = "__asan_set_shadow_";
const char kAsanPoisonStackMemoryName[] = "__asan_poison_stack_memory";
const char kAsanUnpoisonStackMemoryName[] = "__asan_unpoison_stack_memory";
const char kAsanAllocaPoison[] = "__asan_alloca_poison";
const char kAsanAllocasUnpoison[] = "__asan_allocas_unpoison";

static const unsigned kAllocaRzSize = 32;

// This flag may need to be replaced with -f[no]sgxsan-stack.
static cl::opt<bool> ClStack(
    "sgxsan-stack",
    cl::desc("Handle stack memory"),
    cl::Hidden,
    cl::init(true));

static cl::opt<uint32_t> ClMaxInlinePoisoningSize(
    "sgxsan-max-inline-poisoning-size",
    cl::desc("Inline shadow poisoning for blocks up to the given size in bytes."),
    cl::Hidden,
    cl::init(64));

static cl::opt<bool> ClRedzoneByvalArgs(
    "sgxsan-redzone-byval-args",
    cl::desc("Create redzones for byval arguments (extra copy required)"),
    cl::Hidden,
    cl::init(true));

static cl::opt<unsigned> ClRealignStack(
    "sgxsan-realign-stack",
    cl::desc("Realign stack to the value of this flag (power of two)"),
    cl::Hidden,
    cl::init(32));

static cl::opt<int> ClDebugStack(
    "sgxsan-debug-stack",
    cl::desc("debug stack"),
    cl::Hidden,
    cl::init(0));

static cl::opt<bool> ClInstrumentDynamicAllocas(
    "sgxsan-instrument-dynamic-allocas",
    cl::desc("instrument dynamic allocas"),
    cl::Hidden,
    cl::init(true));

static cl::opt<bool> ClUseAfterReturn("sgxsan-use-after-return",
                                      cl::desc("Check stack-use-after-return"),
                                      cl::Hidden, cl::init(true));

static cl::opt<bool> ClDynamicAllocaStack(
    "sgxsan-stack-dynamic-alloca",
    cl::desc("Use dynamic alloca to represent stack variables"), cl::Hidden,
    cl::init(true));

FunctionStackPoisoner::FunctionStackPoisoner(Function &F, AddressSanitizer &ASan)
    : F(F), ASan(ASan), C(ASan.C), IntptrTy(ASan.IntptrTy),
      IntptrPtrTy(PointerType::get(IntptrTy, 0)), Mapping(ASan.Mapping),
      StackAlignment(1 << Mapping.Scale) {}

void FunctionStackPoisoner::copyArgsPassedByValToAllocas()
{
    Instruction *CopyInsertPoint = &F.front().front();

    IRBuilder<> IRB(CopyInsertPoint);
    const DataLayout &DL = F.getParent()->getDataLayout();
    for (Argument &Arg : F.args())
    {
        if (Arg.hasByValAttr())
        {
            Type *Ty = Arg.getParamByValType();
            const Align Alignment =
                DL.getValueOrABITypeAlignment(Arg.getParamAlign(), Ty);

            AllocaInst *AI = IRB.CreateAlloca(
                Ty, nullptr,
                (Arg.hasName() ? SGXSanGetValueName(&Arg) : "Arg" + Twine(Arg.getArgNo())) +
                    ".byval");
            AI->setAlignment(Alignment);
            Arg.replaceAllUsesWith(AI);

            uint64_t AllocSize = DL.getTypeAllocSize(Ty);
            IRB.CreateMemCpy(AI, Alignment, &Arg, Alignment, AllocSize);
        }
    }
}

// ----------------------- Visitors.
/// Collect all Ret instructions, or the musttail call instruction if it
/// precedes the return instruction.
void FunctionStackPoisoner::visitReturnInst(ReturnInst &RI)
{
    if (CallInst *CI = RI.getParent()->getTerminatingMustTailCall())
        RetVec.push_back(CI);
    else
        RetVec.push_back(&RI);
}

/// Collect all Resume instructions.
void FunctionStackPoisoner::visitResumeInst(ResumeInst &RI) { RetVec.push_back(&RI); }

/// Collect all CatchReturnInst instructions.
void FunctionStackPoisoner::visitCleanupReturnInst(CleanupReturnInst &CRI) { RetVec.push_back(&CRI); }

/// Collect Alloca instructions we want (and can) handle.
void FunctionStackPoisoner::visitAllocaInst(AllocaInst &AI)
{
    if (!ASan.isInterestingAlloca(AI))
    {
        if (AI.isStaticAlloca())
        {
            // Skip over allocas that are present *before* the first instrumented
            // alloca, we don't want to move those around.
            if (AllocaVec.empty())
                return;

            StaticAllocasToMoveUp.push_back(&AI);
        }
        return;
    }

    StackAlignment = std::max(StackAlignment, AI.getAlignment());
    if (!AI.isStaticAlloca())
        DynamicAllocaVec.push_back(&AI);
    else
        AllocaVec.push_back(&AI);
}

/// Collect lifetime intrinsic calls to check for use-after-scope
/// errors.
void FunctionStackPoisoner::visitIntrinsicInst(IntrinsicInst &II)
{
    Intrinsic::ID ID = II.getIntrinsicID();
    if (ID == Intrinsic::stackrestore)
        StackRestoreVec.push_back(&II);
    if (ID == Intrinsic::localescape)
        LocalEscapeCall = &II;
    if (!ASan.UseAfterScope)
        return;
    if (!II.isLifetimeStartOrEnd())
        return;
    // Found lifetime intrinsic, add ASan instrumentation if necessary.
    auto *Size = cast<ConstantInt>(II.getArgOperand(0));
    // If size argument is undefined, don't do anything.
    if (Size->isMinusOne())
        return;
    // Check that size doesn't saturate uint64_t and can
    // be stored in IntptrTy.
    const uint64_t SizeValue = Size->getValue().getLimitedValue();
    if (SizeValue == ~0ULL ||
        !ConstantInt::isValueValidForType(IntptrTy, SizeValue))
        return;
    // Find alloca instruction that corresponds to llvm.lifetime argument.
    // Currently we can only handle lifetime markers pointing to the
    // beginning of the alloca.
    AllocaInst *AI = findAllocaForValue(II.getArgOperand(1), true);
    if (!AI)
    {
        HasUntracedLifetimeIntrinsic = true;
        return;
    }
    // We're interested only in allocas we can handle.
    if (!ASan.isInterestingAlloca(*AI))
        return;
    bool DoPoison = (ID == Intrinsic::lifetime_end);
    AllocaPoisonCall APC = {&II, AI, SizeValue, DoPoison};
    if (AI->isStaticAlloca())
        StaticAllocaPoisonCallVec.push_back(APC);
    else if (ClInstrumentDynamicAllocas)
        DynamicAllocaPoisonCallVec.push_back(APC);
}

void FunctionStackPoisoner::visitCallBase(CallBase &CB)
{
    if (CallInst *CI = dyn_cast<CallInst>(&CB))
    {
        HasInlineAsm |= CI->isInlineAsm() && &CB != ASan.LocalDynamicShadow;
        HasReturnsTwiceCall |= CI->canReturnTwice();
    }
}

void FunctionStackPoisoner::initializeCallbacks(Module &M)
{
    IRBuilder<> IRB(*C);
    if (ASan.UseAfterScope)
    {
        AsanPoisonStackMemoryFunc = M.getOrInsertFunction(
            kAsanPoisonStackMemoryName, IRB.getVoidTy(), IntptrTy, IntptrTy);
        AsanUnpoisonStackMemoryFunc = M.getOrInsertFunction(
            kAsanUnpoisonStackMemoryName, IRB.getVoidTy(), IntptrTy, IntptrTy);
    }
    for (size_t Val : {0x00, 0xf1, 0xf2, 0xf3, 0xf5, 0xf8})
    {
        std::ostringstream Name;
        Name << kAsanSetShadowPrefix;
        Name << std::setw(2) << std::setfill('0') << std::hex << Val;
        AsanSetShadowFunc[Val] =
            M.getOrInsertFunction(Name.str(), IRB.getVoidTy(), IntptrTy, IntptrTy);
    }
    AsanAllocaPoisonFunc = M.getOrInsertFunction(
        kAsanAllocaPoison, IRB.getVoidTy(), IntptrTy, IntptrTy);
    AsanAllocasUnpoisonFunc = M.getOrInsertFunction(
        kAsanAllocasUnpoison, IRB.getVoidTy(), IntptrTy, IntptrTy);
}

/// Collect instructions in the entry block after \p InsBefore which initialize
/// permanent storage for a function argument. These instructions must remain in
/// the entry block so that uninitialized values do not appear in backtraces. An
/// added benefit is that this conserves spill slots. This does not move stores
/// before instrumented / "interesting" allocas.
static void findStoresToUninstrumentedArgAllocas(
    AddressSanitizer &ASan, Instruction &InsBefore,
    SmallVectorImpl<Instruction *> &InitInsts)
{
    Instruction *Start = InsBefore.getNextNonDebugInstruction();
    for (Instruction *It = Start; It; It = It->getNextNonDebugInstruction())
    {
        // Argument initialization looks like:
        // 1) store <Argument>, <Alloca> OR
        // 2) <CastArgument> = cast <Argument> to ...
        //    store <CastArgument> to <Alloca>
        // Do not consider any other kind of instruction.
        //
        // Note: This covers all known cases, but may not be exhaustive. An
        // alternative to pattern-matching stores is to DFS over all Argument uses:
        // this might be more general, but is probably much more complicated.
        if (isa<AllocaInst>(It) || isa<CastInst>(It))
            continue;
        if (auto *Store = dyn_cast<StoreInst>(It))
        {
            // The store destination must be an alloca that isn't interesting for
            // ASan to instrument. These are moved up before InsBefore, and they're
            // not interesting because allocas for arguments can be mem2reg'd.
            auto *Alloca = dyn_cast<AllocaInst>(Store->getPointerOperand());
            if (!Alloca || ASan.isInterestingAlloca(*Alloca))
                continue;

            Value *Val = Store->getValueOperand();
            bool IsDirectArgInit = isa<Argument>(Val);
            bool IsArgInitViaCast =
                isa<CastInst>(Val) &&
                isa<Argument>(cast<CastInst>(Val)->getOperand(0)) &&
                // Check that the cast appears directly before the store. Otherwise
                // moving the cast before InsBefore may break the IR.
                Val == It->getPrevNonDebugInstruction();
            bool IsArgInit = IsDirectArgInit || IsArgInitViaCast;
            if (!IsArgInit)
                continue;

            if (IsArgInitViaCast)
                InitInsts.push_back(cast<Instruction>(Val));
            InitInsts.push_back(Store);
            continue;
        }

        // Do not reorder past unknown instructions: argument initialization should
        // only involve casts and stores.
        return;
    }
}

Value *FunctionStackPoisoner::createAllocaForLayout(
    IRBuilder<> &IRB, const ASanStackFrameLayout &L, bool Dynamic)
{
    AllocaInst *Alloca;
    if (Dynamic)
    {
        Alloca = IRB.CreateAlloca(IRB.getInt8Ty(),
                                  ConstantInt::get(IRB.getInt64Ty(), L.FrameSize),
                                  "MyAlloca");
    }
    else
    {
        Alloca = IRB.CreateAlloca(ArrayType::get(IRB.getInt8Ty(), L.FrameSize),
                                  nullptr, "MyAlloca");
        assert(Alloca->isStaticAlloca());
    }
    assert((ClRealignStack & (ClRealignStack - 1)) == 0);
    size_t FrameAlignment = std::max(L.FrameAlignment, (size_t)ClRealignStack);
    Alloca->setAlignment(Align(FrameAlignment));
    return IRB.CreatePointerCast(Alloca, IntptrTy);
}

void FunctionStackPoisoner::copyToShadow(ArrayRef<uint8_t> ShadowMask,
                                         ArrayRef<uint8_t> ShadowBytes,
                                         IRBuilder<> &IRB, Value *ShadowBase)
{
    copyToShadow(ShadowMask, ShadowBytes, 0, ShadowMask.size(), IRB, ShadowBase);
}

void FunctionStackPoisoner::copyToShadow(ArrayRef<uint8_t> ShadowMask,
                                         ArrayRef<uint8_t> ShadowBytes,
                                         size_t Begin, size_t End,
                                         IRBuilder<> &IRB, Value *ShadowBase)
{
    assert(ShadowMask.size() == ShadowBytes.size());
    size_t Done = Begin;
    for (size_t i = Begin, j = Begin + 1; i < End; i = j++)
    {
        if (!ShadowMask[i])
        {
            assert(!ShadowBytes[i]);
            continue;
        }
        uint8_t Val = ShadowBytes[i];
        if (!AsanSetShadowFunc[Val])
            continue;

        // Skip same values.
        for (; j < End && ShadowMask[j] && Val == ShadowBytes[j]; ++j)
        {
        }

        if (j - i >= ClMaxInlinePoisoningSize)
        {
            copyToShadowInline(ShadowMask, ShadowBytes, Done, i, IRB, ShadowBase);
            IRB.CreateCall(AsanSetShadowFunc[Val],
                           {IRB.CreateAdd(ShadowBase, ConstantInt::get(IntptrTy, i)),
                            ConstantInt::get(IntptrTy, j - i)});
            Done = j;
        }
    }

    copyToShadowInline(ShadowMask, ShadowBytes, Done, End, IRB, ShadowBase);
}

void FunctionStackPoisoner::copyToShadowInline(ArrayRef<uint8_t> ShadowMask,
                                               ArrayRef<uint8_t> ShadowBytes,
                                               size_t Begin, size_t End,
                                               IRBuilder<> &IRB,
                                               Value *ShadowBase)
{
    if (Begin >= End)
        return;

    const size_t LargestStoreSizeInBytes =
        std::min<size_t>(sizeof(uint64_t), ASan.LongSize / 8);

    const bool IsLittleEndian = F.getParent()->getDataLayout().isLittleEndian();

    // Poison given range in shadow using larges store size with out leading and
    // trailing zeros in ShadowMask. Zeros never change, so they need neither
    // poisoning nor up-poisoning. Still we don't mind if some of them get into a
    // middle of a store.
    for (size_t i = Begin; i < End;)
    {
        if (!ShadowMask[i])
        {
            assert(!ShadowBytes[i]);
            ++i;
            continue;
        }

        size_t StoreSizeInBytes = LargestStoreSizeInBytes;
        // Fit store size into the range.
        while (StoreSizeInBytes > End - i)
            StoreSizeInBytes /= 2;

        // Minimize store size by trimming trailing zeros.
        for (size_t j = StoreSizeInBytes - 1; j && !ShadowMask[i + j]; --j)
        {
            while (j <= StoreSizeInBytes / 2)
                StoreSizeInBytes /= 2;
        }

        uint64_t Val = 0;
        for (size_t j = 0; j < StoreSizeInBytes; j++)
        {
            if (IsLittleEndian)
                Val |= (uint64_t)ShadowBytes[i + j] << (8 * j);
            else
                Val = (Val << 8) | ShadowBytes[i + j];
        }

        Value *Ptr = IRB.CreateAdd(ShadowBase, ConstantInt::get(IntptrTy, i));
        Value *Poison = IRB.getIntN(StoreSizeInBytes * 8, Val);
        IRB.CreateAlignedStore(
            Poison, IRB.CreateIntToPtr(Ptr, Poison->getType()->getPointerTo()),
            Align(1));

        i += StoreSizeInBytes;
    }
}

void FunctionStackPoisoner::poisonAlloca(Value *V, uint64_t Size,
                                         IRBuilder<> &IRB, bool DoPoison)
{
    // For now just insert the call to ASan runtime.
    Value *AddrArg = IRB.CreatePointerCast(V, IntptrTy);
    Value *SizeArg = ConstantInt::get(IntptrTy, Size);
    IRB.CreateCall(
        DoPoison ? AsanPoisonStackMemoryFunc : AsanUnpoisonStackMemoryFunc,
        {AddrArg, SizeArg});
}

void FunctionStackPoisoner::createDynamicAllocasInitStorage()
{
    BasicBlock &FirstBB = *F.begin();
    IRBuilder<> IRB(dyn_cast<Instruction>(FirstBB.begin()));
    DynamicAllocaLayout = IRB.CreateAlloca(IntptrTy, nullptr);
    IRB.CreateStore(Constant::getNullValue(IntptrTy), DynamicAllocaLayout);
    DynamicAllocaLayout->setAlignment(Align(32));
}

// Handling llvm.lifetime intrinsics for a given %alloca:
// (1) collect all llvm.lifetime.xxx(%size, %value) describing the alloca.
// (2) if %size is constant, poison memory for llvm.lifetime.end (to detect
//     invalid accesses) and unpoison it for llvm.lifetime.start (the memory
//     could be poisoned by previous llvm.lifetime.end instruction, as the
//     variable may go in and out of scope several times, e.g. in loops).
// (3) if we poisoned at least one %alloca in a function,
//     unpoison the whole stack frame at function exit.
void FunctionStackPoisoner::handleDynamicAllocaCall(AllocaInst *AI)
{
    IRBuilder<> IRB(AI);

    const unsigned Alignment = std::max(kAllocaRzSize, AI->getAlignment());
    const uint64_t AllocaRedzoneMask = kAllocaRzSize - 1;

    Value *Zero = Constant::getNullValue(IntptrTy);
    Value *AllocaRzSize = ConstantInt::get(IntptrTy, kAllocaRzSize);
    Value *AllocaRzMask = ConstantInt::get(IntptrTy, AllocaRedzoneMask);

    // Since we need to extend alloca with additional memory to locate
    // redzones, and OldSize is number of allocated blocks with
    // ElementSize size, get allocated memory size in bytes by
    // OldSize * ElementSize.
    const unsigned ElementSize =
        F.getParent()->getDataLayout().getTypeAllocSize(AI->getAllocatedType());
    Value *OldSize =
        IRB.CreateMul(IRB.CreateIntCast(AI->getArraySize(), IntptrTy, false),
                      ConstantInt::get(IntptrTy, ElementSize));

    // PartialSize = OldSize % 32
    Value *PartialSize = IRB.CreateAnd(OldSize, AllocaRzMask);

    // Misalign = kAllocaRzSize - PartialSize;
    Value *Misalign = IRB.CreateSub(AllocaRzSize, PartialSize);

    // PartialPadding = Misalign != kAllocaRzSize ? Misalign : 0;
    Value *Cond = IRB.CreateICmpNE(Misalign, AllocaRzSize);
    Value *PartialPadding = IRB.CreateSelect(Cond, Misalign, Zero);

    // AdditionalChunkSize = Alignment + PartialPadding + kAllocaRzSize
    // Alignment is added to locate left redzone, PartialPadding for possible
    // partial redzone and kAllocaRzSize for right redzone respectively.
    Value *AdditionalChunkSize = IRB.CreateAdd(
        ConstantInt::get(IntptrTy, Alignment + kAllocaRzSize), PartialPadding);

    Value *NewSize = IRB.CreateAdd(OldSize, AdditionalChunkSize);

    // Insert new alloca with new NewSize and Alignment params.
    AllocaInst *NewAlloca = IRB.CreateAlloca(IRB.getInt8Ty(), NewSize);
    NewAlloca->setAlignment(Align(Alignment));

    // NewAddress = Address + Alignment
    Value *NewAddress = IRB.CreateAdd(IRB.CreatePtrToInt(NewAlloca, IntptrTy),
                                      ConstantInt::get(IntptrTy, Alignment));

    // Insert __asan_alloca_poison call for new created alloca.
    IRB.CreateCall(AsanAllocaPoisonFunc, {NewAddress, OldSize});

    // Store the last alloca's address to DynamicAllocaLayout. We'll need this
    // for unpoisoning stuff.
    IRB.CreateStore(IRB.CreatePtrToInt(NewAlloca, IntptrTy), DynamicAllocaLayout);

    Value *NewAddressPtr = IRB.CreateIntToPtr(NewAddress, AI->getType());

    // Replace all uses of AddessReturnedByAlloca with NewAddressPtr.
    AI->replaceAllUsesWith(NewAddressPtr);

    // We are done. Erase old alloca from parent.
    AI->eraseFromParent();
}

void FunctionStackPoisoner::unpoisonDynamicAllocasBeforeInst(Instruction *InstBefore,
                                                             Value *SavedStack)
{
    IRBuilder<> IRB(InstBefore);
    Value *DynamicAreaPtr = IRB.CreatePtrToInt(SavedStack, IntptrTy);
    // When we insert _asan_allocas_unpoison before @llvm.stackrestore, we
    // need to adjust extracted SP to compute the address of the most recent
    // alloca. We have a special @llvm.get.dynamic.area.offset intrinsic for
    // this purpose.
    if (!isa<ReturnInst>(InstBefore))
    {
        Function *DynamicAreaOffsetFunc = Intrinsic::getDeclaration(
            InstBefore->getModule(), Intrinsic::get_dynamic_area_offset,
            {IntptrTy});

        Value *DynamicAreaOffset = IRB.CreateCall(DynamicAreaOffsetFunc, {});

        DynamicAreaPtr = IRB.CreateAdd(IRB.CreatePtrToInt(SavedStack, IntptrTy),
                                       DynamicAreaOffset);
    }

    IRB.CreateCall(
        AsanAllocasUnpoisonFunc,
        {IRB.CreateLoad(IntptrTy, DynamicAllocaLayout), DynamicAreaPtr});
}

// Unpoison dynamic allocas redzones.
void FunctionStackPoisoner::unpoisonDynamicAllocas()
{
    for (Instruction *Ret : RetVec)
        unpoisonDynamicAllocasBeforeInst(Ret, DynamicAllocaLayout);

    for (Instruction *StackRestoreInst : StackRestoreVec)
        unpoisonDynamicAllocasBeforeInst(StackRestoreInst,
                                         StackRestoreInst->getOperand(0));
}

void FunctionStackPoisoner::processDynamicAllocas()
{
    if (!ClInstrumentDynamicAllocas || DynamicAllocaVec.empty())
    {
        assert(DynamicAllocaPoisonCallVec.empty());
        return;
    }

    // Insert poison calls for lifetime intrinsics for dynamic allocas.
    for (const auto &APC : DynamicAllocaPoisonCallVec)
    {
        assert(APC.InsBefore);
        assert(APC.AI);
        assert(ASan.isInterestingAlloca(*APC.AI));
        assert(!APC.AI->isStaticAlloca());

        IRBuilder<> IRB(APC.InsBefore);
        poisonAlloca(APC.AI, APC.Size, IRB, APC.DoPoison);
        // Dynamic allocas will be unpoisoned unconditionally below in
        // unpoisonDynamicAllocas.
        // Flag that we need unpoison static allocas.
    }

    // Handle dynamic allocas.
    createDynamicAllocasInitStorage();
    for (auto &AI : DynamicAllocaVec)
        handleDynamicAllocaCall(AI);
    unpoisonDynamicAllocas();
}

void FunctionStackPoisoner::processStaticAllocas()
{
    if (AllocaVec.empty())
    {
        assert(StaticAllocaPoisonCallVec.empty());
        return;
    }

    int StackMallocIdx = -1;
    DebugLoc EntryDebugLocation;
    if (auto SP = F.getSubprogram())
        EntryDebugLocation =
            DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);

    Instruction *InsBefore = AllocaVec[0];
    IRBuilder<> IRB(InsBefore);

    // Make sure non-instrumented allocas stay in the entry block. Otherwise,
    // debug info is broken, because only entry-block allocas are treated as
    // regular stack slots.
    auto InsBeforeB = InsBefore->getParent();
    assert(InsBeforeB == &F.getEntryBlock());
    for (auto *AI : StaticAllocasToMoveUp)
        if (AI->getParent() == InsBeforeB)
            AI->moveBefore(InsBefore);

    // Move stores of arguments into entry-block allocas as well. This prevents
    // extra stack slots from being generated (to house the argument values until
    // they can be stored into the allocas). This also prevents uninitialized
    // values from being shown in backtraces.
    SmallVector<Instruction *, 8> ArgInitInsts;
    findStoresToUninstrumentedArgAllocas(ASan, *InsBefore, ArgInitInsts);
    for (Instruction *ArgInitInst : ArgInitInsts)
        ArgInitInst->moveBefore(InsBefore);

    // If we have a call to llvm.localescape, keep it in the entry block.
    if (LocalEscapeCall)
        LocalEscapeCall->moveBefore(InsBefore);

    SmallVector<ASanStackVariableDescription, 16> SVD;
    SVD.reserve(AllocaVec.size());
    for (AllocaInst *AI : AllocaVec)
    {
        ASanStackVariableDescription D = {SGXSanGetValueName(AI).data(),
                                          ASan.getAllocaSizeInBytes(*AI),
                                          0,
                                          AI->getAlignment(),
                                          AI,
                                          0,
                                          0};
        SVD.push_back(D);
    }

    // Minimal header size (left redzone) is 4 pointers,
    // i.e. 32 bytes on 64-bit platforms and 16 bytes in 32-bit platforms.
    size_t Granularity = 1ULL << Mapping.Scale;
    size_t MinHeaderSize = std::max((size_t)ASan.LongSize / 2, Granularity);
    const ASanStackFrameLayout &L =
        ComputeASanStackFrameLayout(SVD, Granularity, MinHeaderSize);

    // Build AllocaToSVDMap for ASanStackVariableDescription lookup.
    DenseMap<const AllocaInst *, ASanStackVariableDescription *> AllocaToSVDMap;
    for (auto &Desc : SVD)
        AllocaToSVDMap[Desc.AI] = &Desc;

    // Update SVD with information from lifetime intrinsics.
    for (const auto &APC : StaticAllocaPoisonCallVec)
    {
        assert(APC.InsBefore);
        assert(APC.AI);
        assert(ASan.isInterestingAlloca(*APC.AI));
        assert(APC.AI->isStaticAlloca());

        ASanStackVariableDescription &Desc = *AllocaToSVDMap[APC.AI];
        Desc.LifetimeSize = Desc.Size;
        if (const DILocation *FnLoc = EntryDebugLocation.get())
        {
            if (const DILocation *LifetimeLoc = APC.InsBefore->getDebugLoc().get())
            {
                if (LifetimeLoc->getFile() == FnLoc->getFile())
                    if (unsigned Line = LifetimeLoc->getLine())
                        Desc.Line = std::min(Desc.Line ? Desc.Line : Line, Line);
            }
        }
    }

    auto DescriptionString = ComputeASanStackFrameDescription(SVD);
    LLVM_DEBUG(dbgs() << DescriptionString << " --- " << L.FrameSize << "\n");
    uint64_t LocalStackSize = L.FrameSize;

    Value *StaticAlloca = createAllocaForLayout(IRB, L, false);

    // Value *FakeStack;
    Value *LocalStackBase;
    Value *LocalStackBaseAlloca;
    // uint8_t DIExprFlags = DIExpression::ApplyOffset;

    // void *FakeStack = nullptr;
    // void *LocalStackBase = alloca(LocalStackSize);
    // FakeStack = ConstantInt::get(IntptrTy, 0);
    LocalStackBase = StaticAlloca;
    LocalStackBaseAlloca = LocalStackBase;

    // It shouldn't matter whether we pass an `alloca` or a `ptrtoint` as the
    // dbg.declare address opereand, but passing a `ptrtoint` seems to confuse
    // later passes and can result in dropped variable coverage in debug info.
    Value *LocalStackBaseAllocaPtr =
        isa<PtrToIntInst>(LocalStackBaseAlloca)
            ? cast<PtrToIntInst>(LocalStackBaseAlloca)->getPointerOperand()
            : LocalStackBaseAlloca;
    assert(isa<AllocaInst>(LocalStackBaseAllocaPtr) &&
           "Variable descriptions relative to ASan stack base will be dropped");

    // Replace Alloca instructions with base+offset.
    for (const auto &Desc : SVD)
    {
        AllocaInst *AI = Desc.AI;

        Value *NewAllocaPtr = IRB.CreateIntToPtr(
            IRB.CreateAdd(LocalStackBase, ConstantInt::get(IntptrTy, Desc.Offset)),
            AI->getType());
        AI->replaceAllUsesWith(NewAllocaPtr);
    }

    // The left-most redzone has enough space for at least 4 pointers.
    // Write the Magic value to redzone[0].
    Value *BasePlus0 = IRB.CreateIntToPtr(LocalStackBase, IntptrPtrTy);
    IRB.CreateStore(ConstantInt::get(IntptrTy, kCurrentStackFrameMagic),
                    BasePlus0);
    // Write the frame description constant to redzone[1].
    Value *BasePlus1 = IRB.CreateIntToPtr(
        IRB.CreateAdd(LocalStackBase,
                      ConstantInt::get(IntptrTy, ASan.LongSize / 8)),
        IntptrPtrTy);
    GlobalVariable *StackDescriptionGlobal =
        createPrivateGlobalForString(*F.getParent(), DescriptionString,
                                     /*AllowMerging*/ true, kAsanGenPrefix);
    Value *Description = IRB.CreatePointerCast(StackDescriptionGlobal, IntptrTy);
    IRB.CreateStore(Description, BasePlus1);
    // Write the PC to redzone[2].
    Value *BasePlus2 = IRB.CreateIntToPtr(
        IRB.CreateAdd(LocalStackBase,
                      ConstantInt::get(IntptrTy, 2 * ASan.LongSize / 8)),
        IntptrPtrTy);
    IRB.CreateStore(IRB.CreatePointerCast(&F, IntptrTy), BasePlus2);

    const auto &ShadowAfterScope = GetShadowBytesAfterScope(SVD, L);

    // Poison the stack red zones at the entry.
    Value *ShadowBase = ASan.memToShadow(LocalStackBase, IRB);
    // As mask we must use most poisoned case: red zones and after scope.
    // As bytes we can use either the same or just red zones only.
    copyToShadow(ShadowAfterScope, ShadowAfterScope, IRB, ShadowBase);

    if (!StaticAllocaPoisonCallVec.empty())
    {
        const auto &ShadowInScope = GetShadowBytes(SVD, L);

        // Poison static allocas near lifetime intrinsics.
        for (const auto &APC : StaticAllocaPoisonCallVec)
        {
            const ASanStackVariableDescription &Desc = *AllocaToSVDMap[APC.AI];
            assert(Desc.Offset % L.Granularity == 0);
            size_t Begin = Desc.Offset / L.Granularity;
            size_t End = Begin + (APC.Size + L.Granularity - 1) / L.Granularity;

            IRBuilder<> IRB(APC.InsBefore);
            copyToShadow(ShadowAfterScope,
                         APC.DoPoison ? ShadowAfterScope : ShadowInScope, Begin, End,
                         IRB, ShadowBase);
        }
    }

    SmallVector<uint8_t, 64> ShadowClean(ShadowAfterScope.size(), 0);
    // SmallVector<uint8_t, 64> ShadowAfterReturn;

    // (Un)poison the stack before all ret instructions.
    for (Instruction *Ret : RetVec)
    {
        IRBuilder<> IRBRet(Ret);
        // Mark the current frame as retired.
        IRBRet.CreateStore(ConstantInt::get(IntptrTy, kRetiredStackFrameMagic),
                           BasePlus0);

        copyToShadow(ShadowAfterScope, ShadowClean, IRBRet, ShadowBase);
    }

    // We are done. Remove the old unused alloca instructions.
    for (auto AI : AllocaVec)
        AI->eraseFromParent();
}

void FunctionStackPoisoner::getRetInstVec(SmallVector<Instruction *, 8> &ReturnInstVec)
{
    ReturnInstVec = this->RetVec;
}

bool FunctionStackPoisoner::runOnFunction()
{
    if (!ClStack)
        return false;
    if (ClRedzoneByvalArgs)
        copyArgsPassedByValToAllocas();

    // Collect alloca, ret, lifetime instructions etc.
    for (BasicBlock *BB : depth_first(&F.getEntryBlock()))
        visit(*BB);

    if (AllocaVec.empty() && DynamicAllocaVec.empty())
        return false;

    initializeCallbacks(*F.getParent());

    if (HasUntracedLifetimeIntrinsic)
    {
        // If there are lifetime intrinsics which couldn't be traced back to an
        // alloca, we may not know exactly when a variable enters scope, and
        // therefore should "fail safe" by not poisoning them.
        StaticAllocaPoisonCallVec.clear();
        DynamicAllocaPoisonCallVec.clear();
    }

    processDynamicAllocas();
    processStaticAllocas();

    if (ClDebugStack)
    {
        LLVM_DEBUG(dbgs() << F);
    }
    return true;
}