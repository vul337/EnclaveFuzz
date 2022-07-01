#!/bin/bash
set -e

SGXSAN_DIR="$(pwd)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/..)

# remove old
rm -rf ${SGXSAN_DIR}/SDKLib/
mkdir SDKLib

cd SDKPatch

# patch trts tcxx
echo "== Patch SDK =="
patch -p1 -d ${LINUX_SGX_SRC_DIR} < sdk.patch
# get newer libsgx_trts.a
echo "== Get libsgx_trts.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/trts
make clean -s
make -j$(nproc) "$@" -s
cp linux/libsgx_trts.a ${SGXSAN_DIR}/SDKLib/
cd ../..
# get newer libsgx_trts_sim.a
echo "== Get libsgx_trts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/trtssim
make clean -s
make -j$(nproc) "$@" -s
cp linux/libsgx_trts_sim.a ${SGXSAN_DIR}/SDKLib/
cd ../../..
# get unpatched libsgx_tsafecrt.a
cd ${LINUX_SGX_SRC_DIR}/sdk/tsafecrt
make clean -s
make -j$(nproc) "$@" -s
cp libsgx_tsafecrt.a ${SGXSAN_DIR}/SDKLib/
cd ../..
# get newer libsgx_tservice_sim.a
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/tservice_sim
make clean -s
make -j$(nproc) "$@" -s
cp libsgx_tservice_sim.a ${SGXSAN_DIR}/SDKLib/
# get newer libsgx_tservice.a
cd ${LINUX_SGX_SRC_DIR}/sdk
make tservice -j$(nproc) "$@" -s
cp ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tservice.a ${SGXSAN_DIR}/SDKLib/
cd ..
# get newer libtlibthread.a
cd ${LINUX_SGX_SRC_DIR}/sdk/tlibthread
make clean -s
make -j$(nproc) "$@" -s
cp libtlibthread.a ${SGXSAN_DIR}/SDKLib/
cd ..
