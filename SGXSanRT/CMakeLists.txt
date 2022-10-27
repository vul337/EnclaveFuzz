set(PLTHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../plthook/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_MINI}/common/inc
    ${LINUX_SGX_MINI}/common/inc/internal
    ${LINUX_SGX_MINI}/common/inc/tlibc
    ${LINUX_SGX_MINI}/sdk/tlibthread
    ${PLTHOOK_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

add_library(
    SGXSanRT STATIC 
    Malloc.cpp
    Poison.cpp
    PoisonCheck.cpp
    SGXSanRT.cpp
    ArgShadow.cpp
    MemAccessMgr.cpp
    Sticker.cpp 
    ${LINUX_SGX_MINI}/sdk/tlibc/spinlock.c 
    ${LINUX_SGX_MINI}/sdk/tlibc/string/consttime_memequal.c 
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_cond.cpp
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_mutex.cpp
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_rwlock.cpp
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_utils.cpp
    ${LINUX_SGX_MINI}/psw/urts/enclave_mutex.cpp 
    ${LINUX_SGX_MINI}/common/src/se_event.c
    ${PLTHOOK_DIR}/plthook_elf.c)

set_target_properties(SGXSanRT PROPERTIES POSITION_INDEPENDENT_CODE True)