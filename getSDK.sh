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
PATCH_DIR="$(realpath ${SGXSAN_DIR}/SGXSDKPatch/)"
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
CC=clang
CXX=clang++
Jobs=$(nproc)
ADD_LLVM_FLAGS=
ADD_MAKE_FLAGS="-s"

if [[ "${MODE}" = "DEBUG" ]]
then
    ADD_LLVM_FLAGS+=" -g -O0"
    ADD_MAKE_FLAGS+=" DEBUG=1"
fi

echo "-- ADD_LLVM_FLAGS: ${ADD_LLVM_FLAGS}"
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

# get libsgx_enclave_common.{so,a}
echo "== Get libsgx_enclave_common.{so,a} =="
cd ${LINUX_SGX_SRC_DIR}/psw/enclave_common
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} libsgx_enclave_common.{so,a} ${PREFIX}/lib64/
ln -fs ${PREFIX}/lib64/libsgx_enclave_common.so ${PREFIX}/lib64/libsgx_enclave_common.so.1

# get libsgx_trts.a
echo "== Get libsgx_trts.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/trts
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} linux/libsgx_trts.a ${PREFIX}/lib64/

# get libsgx_trts_sim.a
echo "== Get libsgx_trts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/trtssim
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} linux/libsgx_trts_sim.a ${PREFIX}/lib64

# get libsgx_tcxx.a
echo "== Get libsgx_tcxx.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a
cd ${LINUX_SGX_SRC_DIR}/sdk/cpprt
${MAKE} clean -s
cd ${LINUX_SGX_SRC_DIR}/sdk
${MAKE} tcxx -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a ${PREFIX}/lib64/
