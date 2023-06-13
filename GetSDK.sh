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
PATCH_DIR="$(realpath ${SGXSAN_DIR}/patch/)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/linux-sgx)
LINUX_SGX_DCAP_SRC_DIR=$(realpath ${LINUX_SGX_SRC_DIR}/external/dcap_source)

MODE=${MODE:="RELEASE"}
FUZZER=${FUZZER:="LIBFUZZER"}
SILENT=${SILENT:="TRUE"}
HOST_ASAN=${HOST_ASAN:="FALSE"}

echo "-- MODE: ${MODE}"
echo "-- FUZZER: ${FUZZER}"
echo "-- SILENT: ${SILENT}"
echo "-- HOST_ASAN: ${HOST_ASAN}"

PREFIX="${PREFIX:-${SGXSAN_DIR}/install_dir/${MODE}-${FUZZER}-install}"
echo "-- PREFIX: ${PREFIX}"

MAKE=make
CP=cp
OBJCOPY=objcopy
AR=ar
RM=rm
MKDIR=mkdir
LN=ln
CC=clang-13
CXX=clang++-13
Jobs=$(nproc)
HOST_COMPILE_FLAGS=""
COMMON_COMPILE_FLAGS="-Wno-implicit-exception-spec-mismatch -Wno-unknown-warning-option -Wno-unknown-attributes"
ENCLAVE_COMPILE_FLAGS="-fno-discard-value-names -flegacy-pass-manager -Xclang -load -Xclang ${PREFIX}/lib64/libSGXSanPass.so"
ADD_MAKE_FLAGS="-Orecurse"

if [[ "${MODE}" = "DEBUG" ]]
then
    COMMON_COMPILE_FLAGS+=" -g -O0"
    ADD_MAKE_FLAGS+=" DEBUG=1"
fi

if [[ "${HOST_ASAN}" = "TRUE" ]]
then
    HOST_COMPILE_FLAGS+=" -fsanitize=address"
fi

if [[ "${SILENT}" = "TRUE" ]]
then
    ADD_MAKE_FLAGS+=" -s"
fi

echo "-- CC: ${CC}"
echo "-- CXX: ${CXX}"
echo "-- HOST_COMPILE_FLAGS: ${HOST_COMPILE_FLAGS}"
echo "-- COMMON_COMPILE_FLAGS: ${COMMON_COMPILE_FLAGS}"
echo "-- ENCLAVE_COMPILE_FLAGS: ${ENCLAVE_COMPILE_FLAGS}"
echo "-- ADD_MAKE_FLAGS: ${ADD_MAKE_FLAGS}"

# remove old
${RM} -rf ${PREFIX}/lib64/libsgx_* ${PREFIX}/bin/x64/sgx_sign ${PREFIX}/sgxssl
# prepare directory
${MKDIR} -p ${PREFIX}/lib64 ${PREFIX}/bin/x64 ${PREFIX}/sgxssl

# patch enclave_common & trts tcxx
echo "== Patch sgx_enclave_common.cpp & trts & tcxx =="
if grep -qF "char __bigger_[size()];" ${LINUX_SGX_SRC_DIR}/common/inc/sgx_random_buffers.h
then
    echo "Patching..."
    patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/sdk.patch
else
    echo "Already patched!"
fi

get_host_lib() {
    echo "== Get $2 =="
    cd $1
    ${MAKE} clean -s
    ${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
    ${CP} $2 ${PREFIX}/lib64
}

get_host_lib_orig() {
    echo "== Get $2 =="
    cd $1
    ${MAKE} clean -s
    ${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
    ${CP} $2 ${PREFIX}/lib64
}

get_enclave_lib() {
    echo "== Get $2 =="
    cd $1
    ${MAKE} clean -s
    ${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ENCLAVE_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
    ${CP} $2 ${PREFIX}/lib64
}

get_enclave_lib_orig() {
    echo "== Get $2 =="
    cd $1
    ${MAKE} clean -s
    ${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
    ${CP} $2 ${PREFIX}/lib64
}

########## HOST ##########
get_host_lib "${LINUX_SGX_SRC_DIR}/psw/urts/linux"                                  "libsgx_urts.so"
get_host_lib "${LINUX_SGX_SRC_DIR}/psw/enclave_common"                              "libsgx_enclave_common.so libsgx_enclave_common.a"
${LN} -sf libsgx_enclave_common.so ${PREFIX}/lib64/libsgx_enclave_common.so.1
get_host_lib "${LINUX_SGX_SRC_DIR}/psw/uae_service/linux"                           "libsgx_uae_service.so libsgx_epid.so libsgx_launch.so libsgx_quote_ex.so"
get_host_lib "${LINUX_SGX_SRC_DIR}/sdk/ukey_exchange"                               "libsgx_ukey_exchange.a"
get_host_lib "${LINUX_SGX_SRC_DIR}/sdk/protected_fs/sgx_uprotected_fs"              "libsgx_uprotected_fs.a"
get_host_lib "${LINUX_SGX_SRC_DIR}/sdk/libcapable/linux"                            "libsgx_capable.a libsgx_capable.so"
get_host_lib "${LINUX_SGX_SRC_DIR}/sdk/simulation/uae_service_sim/linux"            "libsgx_uae_service_sim.so libsgx_quote_ex_sim.so libsgx_epid_sim.so"
Jobs=1 get_host_lib "${LINUX_SGX_SRC_DIR}/sdk/simulation/urtssim/"                  "linux/libsgx_urts_sim.so"
get_host_lib "${LINUX_SGX_DCAP_SRC_DIR}/QuoteGeneration/quote_wrapper/ql/linux"     "libsgx_dcap_ql.so"
get_host_lib "${LINUX_SGX_DCAP_SRC_DIR}/QuoteVerification/dcap_quoteverify/linux"   "libsgx_dcap_quoteverify.so libsgx_dcap_qvl_attestation.a libsgx_dcap_qvl_parser.a"
${LN} -sf libsgx_dcap_quoteverify.so ${PREFIX}/lib64/libsgx_dcap_quoteverify.so.1

########## ENCLAVE ##########
get_enclave_lib "${LINUX_SGX_SRC_DIR}/sdk/pthread"                                  "libsgx_pthread.a"
get_enclave_lib "${LINUX_SGX_SRC_DIR}/sdk/tkey_exchange"                            "libsgx_tkey_exchange.a"
get_enclave_lib "${LINUX_SGX_SRC_DIR}/sdk/tlibcrypto"                               "libsgx_tcrypto.a"
get_enclave_lib "${LINUX_SGX_SRC_DIR}/sdk/protected_fs/sgx_tprotected_fs"           "libsgx_tprotected_fs.a"
get_enclave_lib "${LINUX_SGX_SRC_DIR}/sdk/tsafecrt"                                 "libsgx_tsafecrt.a"
get_enclave_lib "${LINUX_SGX_DCAP_SRC_DIR}/QuoteVerification/dcap_tvl"              "libsgx_dcap_tvl.a"
${CP} ${LINUX_SGX_DCAP_SRC_DIR}/QuoteVerification/{dcap_tvl/sgx_dcap_tvl.edl,QvE/Include/sgx_qve_header.h} ${PREFIX}/include
${CP} ${LINUX_SGX_DCAP_SRC_DIR}/QuoteGeneration/quote_wrapper/common/inc/{sgx_ql_lib_common,sgx_ql_quote,sgx_quote_3}.h ${PREFIX}/include
get_enclave_lib "${LINUX_SGX_SRC_DIR}/sdk/simulation/tservice_sim"                  "libsgx_tservice_sim.a"
get_enclave_lib_orig "${LINUX_SGX_SRC_DIR}/sdk/simulation/trtssim"                  "linux/libsgx_trts_sim.a"
get_enclave_lib_orig "${LINUX_SGX_SRC_DIR}/sdk/trts"                                "linux/libsgx_trts.a"

echo "== Get libsgx_tcxx.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tlibcxx
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/cpprt
${MAKE} -C ${LINUX_SGX_SRC_DIR}/sdk tcxx -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a ${PREFIX}/lib64/

echo "== Get libsgx_tstdc.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tstdc.a
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tlibc
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tlibthread
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/compiler-rt
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tsafecrt
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tsetjmp
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tmm_rsrv
${MAKE} -C ${LINUX_SGX_SRC_DIR}/sdk tstdc -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tstdc.a ${PREFIX}/lib64/

echo "== Get libsgx_tservice.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tservice.a
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/selib/linux
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tseal/linux
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/ec_dh_lib
${MAKE} -C ${LINUX_SGX_SRC_DIR}/sdk tservice -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tservice.a ${PREFIX}/lib64/

########## TOOL ##########
echo "== Get sgx_sign =="
cd ${LINUX_SGX_SRC_DIR}/sdk/sign_tool/SignTool
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} sgx_sign ${PREFIX}/bin/x64

echo "== Successfully get SGXSDK ${MODE} =="
