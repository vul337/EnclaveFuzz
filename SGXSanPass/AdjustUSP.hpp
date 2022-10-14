#pragma once

#include "llvm/IR/Function.h"

bool adjustUntrustedSPRegisterAtOcallAllocAndFree(llvm::Function &F);