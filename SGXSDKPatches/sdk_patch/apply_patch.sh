#!/bin/bash
set -e

SGXSAN_DIR="$(realpath $(pwd)/../..)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/..)
FLAGS="$@"

# remove old
rm -f ${SGXSAN_DIR}/output/libsgx_tcxx.a ${SGXSAN_DIR}/output/libsgx_trts.a
# apply patch
patch -p1 -d ${LINUX_SGX_SRC_DIR} < lld_compatible_trts_tcxx.patch
# get newer libsgx_trts.a
cd ${LINUX_SGX_SRC_DIR}/sdk/trts
make clean -s
make -j16 -s ${FLAGS}
mkdir -p ${SGXSAN_DIR}/output
cp linux/libsgx_trts.a ${SGXSAN_DIR}/output/libsgx_trts.a
# get newer libsgx_tcxx.a
rm -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a
cd ${LINUX_SGX_SRC_DIR}/sdk/cpprt
make clean -s
cd ..
make tcxx -j16 -s ${FLAGS}
cp ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a ${SGXSAN_DIR}/output/libsgx_tcxx.a