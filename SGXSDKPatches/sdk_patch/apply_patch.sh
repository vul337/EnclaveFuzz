#!/bin/bash
set -xv
. ../../environment || exit
FLAG=$@
# remove old
rm -f ${SGXSAN_DIR}/output/libsgx_tcxx.a ${SGXSAN_DIR}/output/libsgx_trts.a || exit
# apply patch
patch -p1 -d ${LINUX_SGX_DIR} < lld_compatible_trts_tcxx.patch
# get newer libsgx_trts.a
cd ${LINUX_SGX_DIR}/sdk/trts || exit
make clean -s || exit
make -j16 -s ${FLAG} || exit
cp linux/libsgx_trts.a ${SGXSAN_DIR}/output/libsgx_trts.a || exit
# get newer libsgx_tcxx.a
rm -f ${LINUX_SGX_DIR}/build/linux/libsgx_tcxx.a || exit
cd ${LINUX_SGX_DIR}/sdk/cpprt || exit
make clean -s || exit
cd .. || exit
make tcxx -j16 -s ${FLAG} || exit
cp ${LINUX_SGX_DIR}/build/linux/libsgx_tcxx.a ${SGXSAN_DIR}/output/libsgx_tcxx.a || exit