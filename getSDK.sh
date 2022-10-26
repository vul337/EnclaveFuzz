#!/bin/bash
set -e

for ARG in "$@"
do
   KEY="$(echo $ARG | cut -f1 -d=)"
   VAL="$(echo $ARG | cut -f2 -d=)"
   export "$KEY"="$VAL"
done

PWD=$(pwd)
SGXSAN_DIR="$(realpath ${PWD})"
PATCH_DIR="$(realpath ${SGXSAN_DIR}/SDKPatch/)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/..)
PREFIX="${PREFIX:-${SGXSAN_DIR}/install}"

echo "-- MODE: ${MODE}"
echo "-- PREFIX: ${PREFIX}"

MAKE=make
CP=cp
OBJCOPY=objcopy
AR=ar
RM=rm
MKDIR=mkdir
CC=gcc
CXX=g++
Jobs=$(nproc)
ADD_COMPILE_FLAGS=
APP_COMPILE_FLAGS=
ADD_MAKE_FLAGS=" -j${Jobs} -Orecurse -s"

if [[ "${HOST_ASAN}" = "1" ]]
then
    APP_COMPILE_FLAGS+=" -fsanitize=address"
    CC=clang-13
    CXX=clang++-13
fi

if [[ "${MODE}" = "DEBUG" ]]
then
    ADD_COMPILE_FLAGS+=" -g -O0"
    ADD_MAKE_FLAGS+=" DEBUG=1"
fi

echo "-- CC: ${CC}"
echo "-- CXX: ${CXX}"
echo "-- APP_COMPILE_FLAGS: ${APP_COMPILE_FLAGS}"
echo "-- ADD_COMPILE_FLAGS: ${ADD_COMPILE_FLAGS}"
echo "-- ADD_MAKE_FLAGS: ${ADD_MAKE_FLAGS}"

# prepare directory
${MKDIR} -p ${PREFIX}/lib64 ${PREFIX}/bin/x64
# remove old
${RM} -f ${PREFIX}/lib64/libsgx_*

# patch enclave_common & trts tcxx
echo "== Patch sgx_enclave_common.cpp & trts & tcxx =="
if grep -qF "ehdr = (ElfW(Ehdr) *) &__ImageBase;" ${LINUX_SGX_SRC_DIR}/sdk/cpprt/linux/libunwind/src/se-iterate-phdr.c
then
    echo "Patching..."
    patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/enclave_common.patch
    patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/lld_compatible_trts_tcxx.patch
else
    echo "Already patched!"
fi

if [[ "${HOST_ASAN}" = "1" ]]
then
    echo "== Patch llvm_compatible_psw.patch =="
    if grep -qF "CXXFLAGS += -fPIC -Werror -g" ${LINUX_SGX_SRC_DIR}/psw/enclave_common/Makefile
    then
        echo "Patching..."
        patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/llvm_compatible_psw.patch
    else
        echo "Already patched!"
    fi
fi

# get libsgx_enclave_common.{so,a}
echo "== Get libsgx_enclave_common.{so,a} =="
cd ${LINUX_SGX_SRC_DIR}/psw/enclave_common
${MAKE} clean -s
${MAKE} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${APP_COMPILE_FLAGS} ${ADD_COMPILE_FLAGS}"
${CP} libsgx_enclave_common.{so,a} ${PREFIX}/lib64/
ln -fs ${PREFIX}/lib64/libsgx_enclave_common.so ${PREFIX}/lib64/libsgx_enclave_common.so.1

if [[ "${HOST_ASAN}" = "1" ]]
then
    # get libsgx_urts.so
    echo "== Get libsgx_urts.so =="
    cd ${LINUX_SGX_SRC_DIR}/psw/urts/linux
    ${MAKE} clean -s
    ${MAKE} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${APP_COMPILE_FLAGS} ${ADD_COMPILE_FLAGS}"
    ${CP} libsgx_urts.so ${PREFIX}/lib64/

    # get libsgx_uae_service.so
    echo "== Get libsgx_uae_service.so =="
    cd ${LINUX_SGX_SRC_DIR}/psw/uae_service/linux
    ${MAKE} clean -s
    ${MAKE} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${APP_COMPILE_FLAGS} ${ADD_COMPILE_FLAGS}"
    ${CP} libsgx_{uae_service,epid,launch,quote_ex}.so ${PREFIX}/lib64/
fi

# get libsgx_trts.a
echo "== Get libsgx_trts.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/trts
${MAKE} clean -s
${MAKE} ${ADD_MAKE_FLAGS}
${CP} linux/libsgx_trts.a ${PREFIX}/lib64/

# get libsgx_trts_sim.a
echo "== Get libsgx_trts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/trtssim
${MAKE} clean -s
${MAKE} ${ADD_MAKE_FLAGS}
${CP} linux/libsgx_trts_sim.a ${PREFIX}/lib64

# get libsgx_tcxx.a
echo "== Get libsgx_tcxx.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a
cd ${LINUX_SGX_SRC_DIR}/sdk/cpprt
${MAKE} clean -s
cd ${LINUX_SGX_SRC_DIR}/sdk
${MAKE} tcxx ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a ${PREFIX}/lib64/

echo "== Successfully get SGXSDK =="