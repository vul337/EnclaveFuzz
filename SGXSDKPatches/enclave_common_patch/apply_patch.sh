#!/bin/bash
set -xv
. ../../environment || exit
# remove old
rm -f ${SGXSAN_DIR}/output/libsgx_enclave_common.so ${SGXSAN_DIR}/output/libsgx_enclave_common.a ${SGXSAN_DIR}/output/libsgx_enclave_common.so.1 ${SGXSAN_DIR}/output/libsgx_enclave_common.so.debug
# apply patch
patch -p1 -d ${LINUX_SGX_DIR} < enclave_common.patch
# rebuild
cd ${LINUX_SGX_DIR}/psw/enclave_common || exit
make clean -s || exit
make -j16 -s || exit
# copy newer
cp libsgx_enclave_common.so ${SGXSAN_DIR}/output/libsgx_enclave_common.so || exit
cp libsgx_enclave_common.a ${SGXSAN_DIR}/output/libsgx_enclave_common.a || exit
cp libsgx_enclave_common.so.debug ${SGXSAN_DIR}/output/libsgx_enclave_common.so.debug || exit
cd ${SGXSAN_DIR}/output || exit
ln -s libsgx_enclave_common.so libsgx_enclave_common.so.1 || exit