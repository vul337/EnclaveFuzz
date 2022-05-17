#include "ModuleAddressSanitizer.hpp"
using namespace llvm;

const char kAsanModuleCtorName[] = "asan.module_ctor";
const char kAsanModuleDtorName[] = "asan.module_dtor";
const char kAsanInitName[] = "__asan_init";
const char kAsanGenPrefix[] = "___asan_gen_";
const char kODRGenPrefix[] = "__odr_asan_gen_";
const char kSanCovGenPrefix[] = "__sancov_gen_";
const char kAsanRegisterGlobalsName[] = "__asan_register_globals";
const char kAsanUnregisterGlobalsName[] = "__asan_unregister_globals";
static const uint64_t kAsanCtorAndDtorPriority = 102;

// This flag may need to be replaced with -f[no]asan-globals.
static cl::opt<bool> ClGlobals("sgxsan-globals",
                               cl::desc("Handle global objects"), cl::Hidden,
                               cl::init(true));

static cl::opt<bool>
    ClUsePrivateAlias("sgxsan-use-private-alias",
                      cl::desc("Use private aliases for global variables"),
                      cl::Hidden, cl::init(false));

static cl::opt<bool>
    ClUseOdrIndicator("sgxsan-use-odr-indicator",
                      cl::desc("Use odr indicators to improve ODR reporting"),
                      cl::Hidden, cl::init(false));

ModuleAddressSanitizer::ModuleAddressSanitizer(Module &M, bool UseOdrIndicator)
    : UsePrivateAlias(UseOdrIndicator || ClUsePrivateAlias),
      UseOdrIndicator(UseOdrIndicator || ClUseOdrIndicator)
{
    C = &(M.getContext());
    int LongSize = M.getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    Mapping = getShadowMapping();
}

void ModuleAddressSanitizer::initializeCallbacks(Module &M)
{
    IRBuilder<> IRB(*C);

    // Declare functions that register/unregister globals.
    AsanRegisterGlobals = M.getOrInsertFunction(
        kAsanRegisterGlobalsName, IRB.getVoidTy(), IntptrTy, IntptrTy);
    AsanUnregisterGlobals = M.getOrInsertFunction(
        kAsanUnregisterGlobalsName, IRB.getVoidTy(), IntptrTy, IntptrTy);
}

uint64_t ModuleAddressSanitizer::GetCtorAndDtorPriority()
{
    return kAsanCtorAndDtorPriority;
}

uint64_t ModuleAddressSanitizer::getMinRedzoneSizeForGlobal() const
{
    return getRedzoneSizeForScale(Mapping.Scale);
}

uint64_t ModuleAddressSanitizer::getRedzoneSizeForGlobal(uint64_t SizeInBytes) const
{
    constexpr uint64_t kMaxRZ = 1 << 18;
    const uint64_t MinRZ = getMinRedzoneSizeForGlobal();

    // Calculate RZ, where MinRZ <= RZ <= MaxRZ, and RZ ~ 1/4 * SizeInBytes.
    uint64_t RZ =
        std::max(MinRZ, std::min(kMaxRZ, (SizeInBytes / MinRZ / 4) * MinRZ));

    // Round up to multiple of MinRZ.
    if (SizeInBytes % MinRZ)
        RZ += MinRZ - (SizeInBytes % MinRZ);
    assert((RZ + SizeInBytes) % MinRZ == 0);

    return RZ;
}

Instruction *ModuleAddressSanitizer::CreateAsanModuleDtor(Module &M)
{
    AsanDtorFunction =
        Function::Create(FunctionType::get(Type::getVoidTy(*C), false),
                         GlobalValue::InternalLinkage, kAsanModuleDtorName, &M);
    BasicBlock *AsanDtorBB = BasicBlock::Create(*C, "", AsanDtorFunction);

    return ReturnInst::Create(*C, AsanDtorBB);
}

void ModuleAddressSanitizer::InstrumentGlobalsWithMetadataArray(
    IRBuilder<> &IRB, Module &M, ArrayRef<GlobalVariable *> ExtendedGlobals,
    ArrayRef<Constant *> MetadataInitializers)
{
    assert(ExtendedGlobals.size() == MetadataInitializers.size());
    unsigned N = ExtendedGlobals.size();
    assert(N > 0);

    // On platforms that don't have a custom metadata section, we emit an array
    // of global metadata structures.
    ArrayType *ArrayOfGlobalStructTy =
        ArrayType::get(MetadataInitializers[0]->getType(), N);
    auto AllGlobals = new GlobalVariable(
        M, ArrayOfGlobalStructTy, false, GlobalVariable::InternalLinkage,
        ConstantArray::get(ArrayOfGlobalStructTy, MetadataInitializers), "");
    if (Mapping.Scale > 3)
        AllGlobals->setAlignment(Align(1ULL << Mapping.Scale));

    IRB.CreateCall(AsanRegisterGlobals,
                   {IRB.CreatePointerCast(AllGlobals, IntptrTy),
                    ConstantInt::get(IntptrTy, N)});

    // We also need to unregister globals at the end, e.g., when a shared library
    // gets closed.
    IRBuilder<> IRB_Dtor(CreateAsanModuleDtor(M));
    IRB_Dtor.CreateCall(AsanUnregisterGlobals,
                        {IRB.CreatePointerCast(AllGlobals, IntptrTy),
                         ConstantInt::get(IntptrTy, N)});
}

/// Check if \p G has been created by a trusted compiler pass.
static bool GlobalWasGeneratedByCompiler(GlobalVariable *G)
{
    // Do not instrument @llvm.global_ctors, @llvm.used, etc.
    if (G->getName().startswith("llvm."))
        return true;

    // Do not instrument asan globals.
    if (G->getName().startswith(kAsanGenPrefix) ||
        G->getName().startswith(kSanCovGenPrefix) ||
        G->getName().startswith(kODRGenPrefix))
        return true;

    // Do not instrument gcov counter arrays.
    if (G->getName() == "__llvm_gcov_ctr")
        return true;

    return false;
}

bool ModuleAddressSanitizer::shouldInstrumentGlobal(GlobalVariable *G) const
{
    Type *Ty = G->getValueType();
    LLVM_DEBUG(dbgs() << "GLOBAL: " << *G << "\n");

    if (!Ty->isSized())
        return false;
    if (!G->hasInitializer())
        return false;
    // Only instrument globals of default address spaces
    if (G->getAddressSpace())
        return false;
    if (GlobalWasGeneratedByCompiler(G))
        return false; // Our own globals.
    // Two problems with thread-locals:
    //   - The address of the main thread's copy can't be computed at link-time.
    //   - Need to poison all copies, not just the main thread's one.
    if (G->isThreadLocal())
        return false;
    // For now, just ignore this Global if the alignment is large.
    if (G->getAlignment() > getMinRedzoneSizeForGlobal())
        return false;

    // For non-COFF targets, only instrument globals known to be defined by this
    // TU.
    // FIXME: We can instrument comdat globals on ELF if we are using the
    // GC-friendly metadata scheme.
    if (!G->hasExactDefinition() || G->hasComdat())
        return false;

    // If a comdat is present, it must have a selection kind that implies ODR
    // semantics: no duplicates, any, or exact match.
    if (Comdat *C = G->getComdat())
    {
        switch (C->getSelectionKind())
        {
        case Comdat::Any:
        case Comdat::ExactMatch:
        case Comdat::NoDuplicates:
            break;
        case Comdat::Largest:
        case Comdat::SameSize:
            return false;
        }
    }

    if (G->hasSection())
    {
        StringRef Section = G->getSection();

        // Globals from llvm.metadata aren't emitted, do not instrument them.
        if (Section == "llvm.metadata")
            return false;
        // Do not instrument globals from special LLVM sections.
        if (Section.find("__llvm") != StringRef::npos || Section.find("__LLVM") != StringRef::npos)
            return false;

        // Do not instrument function pointers to initialization and termination
        // routines: dynamic linker will not properly handle redzones.
        if (Section.startswith(".preinit_array") ||
            Section.startswith(".init_array") ||
            Section.startswith(".fini_array"))
        {
            return false;
        }

        // Do not instrument user-defined sections (with names resembling
        // valid C identifiers)
        if (llvm::all_of(Section,
                         [](char c)
                         { return llvm::isAlnum(c) || c == '_'; }))
            return false;
    }

    return true;
}

// This function replaces all global variables with new variables that have
// trailing redzones. It also creates a function that poisons
// redzones and inserts this function into llvm.global_ctors.
// Sets *CtorComdat to true if the global registration code emitted into the
// asan constructor is comdat-compatible.
bool ModuleAddressSanitizer::InstrumentGlobals(IRBuilder<> &IRB, Module &M,
                                               bool *CtorComdat)
{
    *CtorComdat = false;

    // Build set of globals that are aliased by some GA, where
    // getExcludedAliasedGlobal(GA) returns the relevant GlobalVariable.

    SmallVector<GlobalVariable *, 16> GlobalsToChange;
    for (auto &G : M.globals())
    {
        if (shouldInstrumentGlobal(&G))
            GlobalsToChange.push_back(&G);
    }

    size_t n = GlobalsToChange.size();
    if (n == 0)
    {
        *CtorComdat = true;
        return false;
    }

    auto &DL = M.getDataLayout();

    // A global is described by a structure
    //   size_t beg;
    //   size_t size;
    //   size_t size_with_redzone;
    //   const char *name;
    //   const char *module_name;
    //   size_t has_dynamic_init;(need front-end info, removed)
    //   void *source_location;(need front-end info, removed)
    //   size_t odr_indicator;
    // We initialize an array of such structures and pass it to a run-time call.
    StructType *GlobalStructTy =
        StructType::get(IntptrTy, IntptrTy, IntptrTy, IntptrTy, IntptrTy,
                        IntptrTy);
    SmallVector<GlobalVariable *, 16> NewGlobals(n);
    SmallVector<Constant *, 16> Initializers(n);

    // We shouldn't merge same module names, as this string serves as unique
    // module ID in runtime.
    GlobalVariable *ModuleName = createPrivateGlobalForString(
        M, M.getModuleIdentifier(), /*AllowMerging*/ false, kAsanGenPrefix);

    for (size_t i = 0; i < n; i++)
    {
        GlobalVariable *G = GlobalsToChange[i];
        StringRef NameForGlobal = G->getName();
        // Create string holding the global name (use global name from metadata
        // if it's available, otherwise just write the name of global variable).
        GlobalVariable *Name = createPrivateGlobalForString(
            M, NameForGlobal, /*AllowMerging*/ true, kAsanGenPrefix);

        Type *Ty = G->getValueType();
        const uint64_t SizeInBytes = DL.getTypeAllocSize(Ty);
        assert(SizeInBytes > 0);
        const uint64_t RightRedzoneSize = getRedzoneSizeForGlobal(SizeInBytes);
        Type *RightRedZoneTy = ArrayType::get(IRB.getInt8Ty(), RightRedzoneSize);

        StructType *NewTy = StructType::get(Ty, RightRedZoneTy);
        Constant *NewInitializer = ConstantStruct::get(
            NewTy, G->getInitializer(), Constant::getNullValue(RightRedZoneTy));

        // Create a new global variable with enough space for a redzone.
        GlobalValue::LinkageTypes Linkage = G->getLinkage();
        if (G->isConstant() && Linkage == GlobalValue::PrivateLinkage)
            Linkage = GlobalValue::InternalLinkage;
        GlobalVariable *NewGlobal =
            new GlobalVariable(M, NewTy, G->isConstant(), Linkage, NewInitializer,
                               "", G, G->getThreadLocalMode());
        NewGlobal->copyAttributesFrom(G);
        NewGlobal->setComdat(G->getComdat());
        NewGlobal->setAlignment(MaybeAlign(getMinRedzoneSizeForGlobal()));
        // Don't fold globals with redzones. ODR violation detector and redzone
        // poisoning implicitly creates a dependence on the global's address, so it
        // is no longer valid for it to be marked unnamed_addr.
        NewGlobal->setUnnamedAddr(GlobalValue::UnnamedAddr::None);

        // Transfer the debug info and type metadata.  The payload starts at offset
        // zero so we can copy the metadata over as is.
        NewGlobal->copyMetadata(G, 0);

        Value *Indices2[2];
        Indices2[0] = IRB.getInt32(0);
        Indices2[1] = IRB.getInt32(0);

        llvm::Constant *C = ConstantExpr::getGetElementPtr(NewTy, NewGlobal, Indices2, true);
        G->replaceAllUsesWith(C);
        NewGlobal->takeName(G);
        G->eraseFromParent();
        NewGlobals[i] = NewGlobal;

        Constant *ODRIndicator = ConstantExpr::getNullValue(IRB.getInt8PtrTy());
        GlobalValue *InstrumentedGlobal = NewGlobal;

        bool CanUsePrivateAliases = true;
        if (CanUsePrivateAliases && UsePrivateAlias)
        {
            // Create local alias for NewGlobal to avoid crash on ODR between
            // instrumented and non-instrumented libraries.
            InstrumentedGlobal =
                GlobalAlias::create(GlobalValue::PrivateLinkage, "", NewGlobal);
        }

        // ODR should not happen for local linkage.
        if (NewGlobal->hasLocalLinkage())
        {
            ODRIndicator = ConstantExpr::getIntToPtr(ConstantInt::get(IntptrTy, -1),
                                                     IRB.getInt8PtrTy());
        }
        else if (UseOdrIndicator)
        {
            // With local aliases, we need to provide another externally visible
            // symbol __odr_asan_XXX to detect ODR violation.
            auto *ODRIndicatorSym =
                new GlobalVariable(M, IRB.getInt8Ty(), false, Linkage,
                                   Constant::getNullValue(IRB.getInt8Ty()),
                                   kODRGenPrefix + NameForGlobal, nullptr,
                                   NewGlobal->getThreadLocalMode());

            // Set meaningful attributes for indicator symbol.
            ODRIndicatorSym->setVisibility(NewGlobal->getVisibility());
            ODRIndicatorSym->setDLLStorageClass(NewGlobal->getDLLStorageClass());
            ODRIndicatorSym->setAlignment(Align(1));
            ODRIndicator = ODRIndicatorSym;
        }

        Constant *Initializer = ConstantStruct::get(
            GlobalStructTy,
            ConstantExpr::getPointerCast(InstrumentedGlobal, IntptrTy),
            ConstantInt::get(IntptrTy, SizeInBytes),
            ConstantInt::get(IntptrTy, SizeInBytes + RightRedzoneSize),
            ConstantExpr::getPointerCast(Name, IntptrTy),
            ConstantExpr::getPointerCast(ModuleName, IntptrTy),
            ConstantExpr::getPointerCast(ODRIndicator, IntptrTy));

        LLVM_DEBUG(dbgs() << "NEW GLOBAL: " << *NewGlobal << "\n");

        Initializers[i] = Initializer;
    }

    // Add instrumented globals to llvm.compiler.used list to avoid LTO from
    // ConstantMerge'ing them.
    SmallVector<GlobalValue *, 16> GlobalsToAddToUsedList;
    for (size_t i = 0; i < n; i++)
    {
        GlobalVariable *G = NewGlobals[i];
        if (G->getName().empty())
            continue;
        GlobalsToAddToUsedList.push_back(G);
    }
    appendToCompilerUsed(M, ArrayRef<GlobalValue *>(GlobalsToAddToUsedList));

    InstrumentGlobalsWithMetadataArray(IRB, M, NewGlobals, Initializers);

    LLVM_DEBUG(dbgs() << M);
    return true;
}

bool ModuleAddressSanitizer::instrumentModule(Module &M)
{
    initializeCallbacks(M);

    // Create a module constructor. A destructor is created lazily because not all
    // platforms, and not all modules need it.
    std::tie(AsanCtorFunction, std::ignore) = createSanitizerCtorAndInitFunctions(M, kAsanModuleCtorName,
                                                                                  kAsanInitName, /*InitArgTypes=*/{},
                                                                                  /*InitArgs=*/{}, "");

    bool CtorComdat = true;
    if (ClGlobals)
    {
        IRBuilder<> IRB(AsanCtorFunction->getEntryBlock().getTerminator());
        InstrumentGlobals(IRB, M, &CtorComdat);
    }

    const uint64_t Priority = GetCtorAndDtorPriority();

    // Put the constructor and destructor in comdat if both
    // (1) global instrumentation is not TU-specific
    // (2) target is ELF.
    appendToGlobalCtors(M, AsanCtorFunction, Priority);
    if (AsanDtorFunction)
        appendToGlobalDtors(M, AsanDtorFunction, Priority);

    return true;
}