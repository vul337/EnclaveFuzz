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
PATCH_DIR="$(realpath ${SGXSAN_DIR}/Patch/)"
LINUX_SGX_SRC_DIR=$(realpath ${SGXSAN_DIR}/linux-sgx)

MODE=${MODE:="RELEASE"}
FUZZER=${FUZZER:="LIBFUZZER"}
SILENT=${SILENT:="TRUE"}

echo "-- MODE: ${MODE}"
echo "-- FUZZER: ${FUZZER}"
echo "-- SILENT: ${SILENT}"

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
HOST_COMPILE_FLAGS=
COMMON_COMPILE_FLAGS="-Wno-unknown-warning-option -Wno-unknown-attributes"
ENCLAVE_COMPILE_FLAGS="-fno-discard-value-names -flegacy-pass-manager -Xclang -load -Xclang ${PREFIX}/lib64/libSGXSanPass.so"
ADD_MAKE_FLAGS=" -Orecurse"

if [[ "${HOST_ASAN}" = "1" ]]
then
    HOST_COMPILE_FLAGS+=" -fsanitize=address"
fi

if [[ "${MODE}" = "DEBUG" ]]
then
    COMMON_COMPILE_FLAGS+=" -g -O0"
    ADD_MAKE_FLAGS+=" DEBUG=1"
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


# prepare directory
${MKDIR} -p ${PREFIX}/lib64 ${PREFIX}/bin/x64
# remove old
${RM} -f ${PREFIX}/lib64/libsgx_* ${PREFIX}/bin/x64/sgx_sign

# patch enclave_common & trts tcxx
echo "== Patch sgx_enclave_common.cpp & trts & tcxx =="
if grep -qF "ehdr = (ElfW(Ehdr) *) &__ImageBase;" ${LINUX_SGX_SRC_DIR}/sdk/cpprt/linux/libunwind/src/se-iterate-phdr.c
then
    echo "Patching..."
    patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/sdk.patch
else
    echo "Already patched!"
fi

########## HOST ##########
# get libsgx_enclave_common.{so,a}
echo "== Get libsgx_enclave_common.{so,a} =="
cd ${LINUX_SGX_SRC_DIR}/psw/enclave_common
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_enclave_common.{so,a} ${PREFIX}/lib64/
${LN} -sf libsgx_enclave_common.so ${PREFIX}/lib64/libsgx_enclave_common.so.1

# get libsgx_ukey_exchange.a
echo "== Get libsgx_ukey_exchange.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/ukey_exchange
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_ukey_exchange.a ${PREFIX}/lib64

# get libsgx_uprotected_fs.a
echo "== Get libsgx_uprotected_fs.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/protected_fs/sgx_uprotected_fs
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_uprotected_fs.a ${PREFIX}/lib64

# get libsgx_urts.so
echo "== Get libsgx_urts.so =="
cd ${LINUX_SGX_SRC_DIR}/psw/urts/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_urts.so ${PREFIX}/lib64/

# get libsgx_urts_sim.so
echo "== Get libsgx_urts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/urtssim/
${MAKE} clean -s
${MAKE} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} linux/libsgx_urts_sim.so ${PREFIX}/lib64

# get libsgx_{uae_service,epid,launch,quote_ex}.so
echo "== Get libsgx_{uae_service,epid,launch,quote_ex}.so =="
cd ${LINUX_SGX_SRC_DIR}/psw/uae_service/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_{uae_service,epid,launch,quote_ex}.so ${PREFIX}/lib64/

#get {libsgx_uae_service_sim,libsgx_quote_ex_sim,libsgx_epid_sim}.so
echo "== Get {libsgx_uae_service_sim,libsgx_quote_ex_sim,libsgx_epid_sim}.so =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/uae_service_sim/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} {libsgx_uae_service_sim,libsgx_quote_ex_sim,libsgx_epid_sim}.so ${PREFIX}/lib64

#get libsgx_capable.{a,so}
echo "== Get libsgx_capable.{a,so} =="
cd ${LINUX_SGX_SRC_DIR}/sdk/libcapable/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_capable.{a,so} ${PREFIX}/lib64

#get libsgx_dcap_ql.so
echo "== Get libsgx_dcap_ql.so =="
cd ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_dcap_ql.so ${PREFIX}/lib64

#get libsgx_dcap_quoteverify.so {libsgx_dcap_qvl_attestation,libsgx_dcap_qvl_parser}.a
echo "== Get libsgx_dcap_quoteverify.so {libsgx_dcap_qvl_attestation,libsgx_dcap_qvl_parser}.a =="
cd ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
${CP} libsgx_dcap_quoteverify.so ${PREFIX}/lib64
${CP} {libsgx_dcap_qvl_attestation,libsgx_dcap_qvl_parser}.a ${PREFIX}/lib64
${LN} -sf libsgx_dcap_quoteverify.so ${PREFIX}/lib64/libsgx_dcap_quoteverify.so.1

########## ENCLAVE ##########
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

# get libsgx_tservice_sim.a
echo "== Get libsgx_tservice_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/tservice_sim
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${COMMON_COMPILE_FLAGS} ${ENCLAVE_COMPILE_FLAGS}"
${CP} libsgx_tservice_sim.a ${PREFIX}/lib64

# get libsgx_pthread.a
echo "== Get libsgx_pthread.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/pthread
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${COMMON_COMPILE_FLAGS} ${ENCLAVE_COMPILE_FLAGS}"
${CP} libsgx_pthread.a ${PREFIX}/lib64

# get libsgx_tkey_exchange.a
echo "== Get libsgx_tkey_exchange.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/tkey_exchange
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${COMMON_COMPILE_FLAGS} ${ENCLAVE_COMPILE_FLAGS}"
${CP} libsgx_tkey_exchange.a ${PREFIX}/lib64

# get libsgx_tcrypto.a
echo "== Get libsgx_tcrypto.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/tlibcrypto
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${COMMON_COMPILE_FLAGS} ${ENCLAVE_COMPILE_FLAGS}"
${CP} libsgx_tcrypto.a ${PREFIX}/lib64

# get libsgx_tcxx.a
echo "== Get libsgx_tcxx.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tlibcxx
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/cpprt
${MAKE} -C ${LINUX_SGX_SRC_DIR}/sdk tcxx -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tcxx.a ${PREFIX}/lib64/

# get libsgx_tstdc.a
echo "== Get libsgx_tstdc.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tstdc.a
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tlibc
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tlibthread
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/compiler-rt
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tsafecrt
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tsetjmp
# ${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tmm_rsrv
${MAKE} -C ${LINUX_SGX_SRC_DIR}/sdk tstdc -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tstdc.a ${PREFIX}/lib64/

# get libsgx_tservice.a
echo "== Get libsgx_tservice.a =="
${RM} -f ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tservice.a
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/selib/linux
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/tseal/linux
${MAKE} clean -s -C ${LINUX_SGX_SRC_DIR}/sdk/ec_dh_lib
${MAKE} -C ${LINUX_SGX_SRC_DIR}/sdk tservice -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} ${LINUX_SGX_SRC_DIR}/build/linux/libsgx_tservice.a ${PREFIX}/lib64/

########## TOOL ##########
#get sgx_sign
echo "== Get sgx_sign =="
cd ${LINUX_SGX_SRC_DIR}/sdk/sign_tool/SignTool
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} sgx_sign ${PREFIX}/bin/x64

echo "== Successfully get SGXSDK ${MODE} =="
