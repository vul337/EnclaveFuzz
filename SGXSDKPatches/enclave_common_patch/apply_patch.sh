#!/bin/bash
set -xv
. ../../environment || exit
FLAG=$@
# remove old
rm -f ${SGXSAN_DIR}/output/libsgx_enclave_common.so ${SGXSAN_DIR}/output/libsgx_enclave_common.a ${SGXSAN_DIR}/output/libsgx_enclave_common.so.1
# apply patch
patch -p1 -d ${LINUX_SGX_DIR} < enclave_common.patch
# rebuild
cd ${LINUX_SGX_DIR}/psw/enclave_common || exit
make clean -s || exit
make -j16 -s ${FLAG} || exit
# copy newer
cp libsgx_enclave_common.so ${SGXSAN_DIR}/output/libsgx_enclave_common.so || exit
cp libsgx_enclave_common.a ${SGXSAN_DIR}/output/libsgx_enclave_common.a || exit
cd ${SGXSAN_DIR}/output || exit
ln -s libsgx_enclave_common.so libsgx_enclave_common.so.1 || exit