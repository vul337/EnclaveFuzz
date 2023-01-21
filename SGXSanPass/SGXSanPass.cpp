#include "AddressSanitizer.h"
#include "FuncRenamePass.h"
#include "SensitiveLeakSanitizer.h"
#include "nlohmann/json.hpp"
#include "llvm/IR/IRBuilder.h"
#include <filesystem>

using ordered_json = nlohmann::ordered_json;
using namespace llvm;

static cl::opt<bool>
    ClEnableSLSan("enable-slsan",
                  cl::desc("Whether enable Sensitive Leak Santizer or not"),
                  cl::Hidden, cl::init(false));

static cl::opt<bool> ClDumpStructType("dump-struct", cl::desc("Dump Struct"),
                                      cl::Hidden, cl::init(false));

static cl::opt<std::string>
    ClEdlJsonFile("edl-json-sgxsan-pass", cl::init("Enclave.edl.json"),
                  cl::desc("Path of *.edl.json generated by EdlParser.py"),
                  cl::Hidden);

static cl::opt<bool> ClLogEnterECall("log-enter-ecall", cl::init(false),
                                     cl::desc("Log when entering ECall"),
                                     cl::Hidden);

namespace {
struct SGXSanLegacyPass : public ModulePass {
  static char ID;
  SGXSanLegacyPass() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    if (ClEnableSLSan) {
      AU.addRequired<CFLSteensAAWrapperPass>();
    }
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }

  bool LogEnterECall(Module &M) {
    bool changed = false;
    if (ClLogEnterECall) {
      std::string EdlJsonFile = ClEdlJsonFile;
      if (std::filesystem::exists(std::filesystem::path(EdlJsonFile))) {
        auto edlJson = ordered_json::parse(ReadFile(EdlJsonFile));
        for (auto &[key, val] : edlJson["trusted"].items()) {
          if (Function *F = M.getFunction(key)) {
            llvm::IRBuilder IRB(&F->front().front());
            auto SGXSanLogEnter = M.getOrInsertFunction(
                "SGXSanLogEnter", IRB.getVoidTy(), IRB.getInt8PtrTy());
            auto funcName = IRB.CreateGlobalStringPtr(F->getName());
            IRB.CreateCall(SGXSanLogEnter, {funcName});
            changed = true;
          }
        }
      }
    }
    return changed;
  }

  void DumpModuleStructs(Module &M) {
    if (ClDumpStructType) {
      ordered_json json;
      for (auto structTy : M.getIdentifiedStructTypes()) {
        TypeSerialize::Serializer serializer;
        serializer.SerializeStructType(structTy, json);
      }
      std::ofstream ofs(M.getName().str() + ".sgxsan.typeinfo.json");
      ofs << json.dump(4);
    }
  }

  bool runOnModule(Module &M) override {
    bool Changed = false;

    DumpModuleStructs(M);
    Changed |= RenameFuncSym(M);
    Changed |= LogEnterECall(M);

    // run SLSan Pass
    if (ClEnableSLSan) {
      dbgs() << "== SLSan Pass: " << M.getName().str() << " ==\n";
      SensitiveLeakSanitizer SLSan(M);
      Changed |= SLSan.runOnModule(
          M, getAnalysis<CFLSteensAAWrapperPass>().getResult());
    }

    // run SGXSan Pass
    dbgs() << "== SGXSan Pass: " << M.getName().str() << " ==\n";
    GlobalsMetadata GlobalsMD = GlobalsMetadata(M);
    AddressSanitizer ASan(M, &GlobalsMD, false, false, true,
                          AsanDetectStackUseAfterReturnMode::Never);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      const TargetLibraryInfo *TLI =
          &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
      Changed |= ASan.instrumentFunction(F, TLI);
    }
    ModuleAddressSanitizer MASan(M, &GlobalsMD);
    Changed |= MASan.instrumentModule(M);
    return Changed;
  }
}; // end of struct SGXSanLegacyPass
} // end of anonymous namespace

char SGXSanLegacyPass::ID = 0;

static RegisterStandardPasses register_lto_pass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });

static RegisterStandardPasses l0_register_std_pass(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });
