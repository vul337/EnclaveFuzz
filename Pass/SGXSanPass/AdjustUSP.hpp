#pragma once

#include "llvm/IR/Function.h"

void adjustUntrustedSPRegisterAtOcallAllocAndFree(llvm::Function &F);