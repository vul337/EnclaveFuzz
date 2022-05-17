#!/bin/bash
set -e

SGXSAN_DIR="$(realpath $(pwd)/../..)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/..)
FLAGS="$@"

# remove old
rm -f ${SGXSAN_DIR}/output/libsgx_enclave_common.*
# apply patch
patch -p1 -d ${LINUX_SGX_SRC_DIR} < enclave_common.patch
# rebuild
cd ${LINUX_SGX_SRC_DIR}/psw/enclave_common
make clean -s
make -j16 -s ${FLAGS}
# copy newer
mkdir -p ${SGXSAN_DIR}/output
cp libsgx_enclave_common.so ${SGXSAN_DIR}/output/libsgx_enclave_common.so
cp libsgx_enclave_common.a ${SGXSAN_DIR}/output/libsgx_enclave_common.a
cd ${SGXSAN_DIR}/output
ln -s libsgx_enclave_common.so libsgx_enclave_common.so.1