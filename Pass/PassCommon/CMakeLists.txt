# it's a component of other targets
add_library(PassCommon PassCommon.cpp SGXSanInstVisitor.cpp)

set_target_properties(PassCommon PROPERTIES POSITION_INDEPENDENT_CODE ON)
