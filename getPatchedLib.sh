#!/bin/bash
SGXSAN_DIR="$(pwd)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/..)

mkdir -p output

# remove old
rm -f ${SGXSAN_DIR}/output/libsgx_enclave_common.* ${SGXSAN_DIR}/output/libsgx_{tcxx,trts}.a

cd SGXSDKPatches

# patch enclave common
echo "<<<Patching enclave common...>>>"
patch -p1 -d ${LINUX_SGX_SRC_DIR} < enclave_common.patch
# rebuild
cd ${LINUX_SGX_SRC_DIR}/psw/enclave_common
make clean -s
make -j$(nproc) -s "$@"
# copy newer
cp libsgx_enclave_common.{so,a} ${SGXSAN_DIR}/output/
cd ${SGXSAN_DIR}/output
ln -fs libsgx_enclave_common.so libsgx_enclave_common.so.1

# patch trts tcxx
patch -p1 -d ${LINUX_SGX_SRC_DIR} < lld_compatible_trts_tcxx.patch
# get newer libsgx_trts.a
echo "<<<Patching trts...>>>"
cd ${LINUX_SGX_SRC_DIR}/sdk/trts
make clean -s
make -j$(nproc) -s "$@"
cp linux/libsgx_trts.a ${SGXSAN_DIR}/output/
# get newer libsgx_tcxx.a
echo "<<<Patching tcxx...>>>"
rm -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a
cd ${LINUX_SGX_SRC_DIR}/sdk/cpprt
make clean -s
cd ..
make tcxx -j$(nproc) -s "$@"
cp ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a ${SGXSAN_DIR}/output/