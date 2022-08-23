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
PATCH_DIR="$(realpath ${SGXSAN_DIR}/SGXSanRT/linux-sgx-mini/)"
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
ADD_LLVM_FLAGS="-Wno-implicit-exception-spec-mismatch -Wno-unknown-warning-option -fno-discard-value-names -flegacy-pass-manager -Xclang -load -Xclang ${PREFIX}/lib64/libSGXSanPass.so"
ADD_MAKE_FLAGS=
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
${RM} -f ${PREFIX}/lib64/libsgx_* ${PREFIX}/bin/x64/sgx_edger8r

# patch trts tcxx
echo "== Patch SDK =="
if grep -qF "char __bigger_[size()];" ${LINUX_SGX_SRC_DIR}/common/inc/sgx_random_buffers.h
then
    echo "Patching..."
    patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/sdk.patch
else
    echo "Already patched!"
fi

# get libsgx_trts_sim.a
echo "== Get libsgx_trts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/trtssim
${MAKE} clean -s
${MAKE} "$@" -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}"
${CP} linux/libsgx_trts_sim.a ${PREFIX}/lib64
${OBJCOPY} --redefine-sym __tls_get_addr=_deleted__tls_get_addr --redefine-sym __cxa_atexit=_deleted__cxa_atexit --redefine-sym sgx_ocall=_deleted_sgx_ocall -W get_thread_data -W sgx_is_within_enclave -W sgx_is_outside_enclave -W sgx_ocalloc -W sgx_ocfree ${PREFIX}/lib64/libsgx_trts_sim.a

# get libsgx_tservice_sim.a
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/tservice_sim
${MAKE} clean -s
${MAKE} "$@" -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}"
${CP} libsgx_tservice_sim.a ${PREFIX}/lib64

# get libsgx_tsafecrt.a
cd ${LINUX_SGX_SRC_DIR}/sdk/tsafecrt
${MAKE} clean -s
${MAKE} "$@" -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}"
${CP} libsgx_tsafecrt.a ${PREFIX}/lib64

#get libsgx_tcrypto.a
cd ${LINUX_SGX_SRC_DIR}/sdk/tlibcrypto
${MAKE} clean -s
${MAKE} "$@" -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}"
${CP} libsgx_tcrypto.a ${PREFIX}/lib64
