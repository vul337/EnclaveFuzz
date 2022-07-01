#include "PassUtil.h"

using namespace llvm;

std::map<BasicBlock *, VisitInfo> SGXSanInstVisitor::BasicBlockVisitInfoMap;
std::map<Function *, VisitInfo> SGXSanInstVisitor::FunctionVisitInfoMap;
std::map<Module *, VisitInfo> SGXSanInstVisitor::ModuleVisitInfoMap;
