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

MODE=${MODE:="RELEASE"}
FUZZER=${FUZZER:="LIBFUZZER"}
SILENT=${SILENT:="TRUE"}
SDK_VER=${SDK_VER:="2_19"}

echo "-- MODE: ${MODE}"
echo "-- FUZZER: ${FUZZER}"
echo "-- SDK_VER: ${SDK_VER}"

PREFIX="${PREFIX:-${SGXSAN_DIR}/install_dir/${MODE}-${FUZZER}-install}"
echo "-- PREFIX: ${PREFIX}"

MAKE=make
CP=cp
OBJCOPY=objcopy
AR=ar
RM=rm
MKDIR=mkdir
CC=clang-13
CXX=clang++-13
LN=ln
Jobs=$(nproc)
ADD_LLVM_FLAGS="-Wno-implicit-exception-spec-mismatch -Wno-unknown-warning-option -Wno-deprecated-declarations -fno-discard-value-names -flegacy-pass-manager -Xclang -load -Xclang ${PREFIX}/lib64/libSGXSanPass.so"
ADD_MAKE_FLAGS="-Orecurse"
if [[ "${MODE}" = "DEBUG" ]]
then
    ADD_LLVM_FLAGS+=" -g -O0"
    ADD_MAKE_FLAGS+=" DEBUG=1"
fi

if [[ "${FUZZER}" = "LIBFUZZER" ]]
then
    ADD_LLVM_FLAGS+=" -fsanitize-coverage=inline-8bit-counters,bb,no-prune,pc-table,trace-cmp -fprofile-instr-generate -fcoverage-mapping"
fi

if [[ "${SILENT}" = "TRUE" ]]
then
    ADD_MAKE_FLAGS+=" -s"
fi

echo "-- ADD_LLVM_FLAGS: ${ADD_LLVM_FLAGS}"
echo "-- ADD_MAKE_FLAGS: ${ADD_MAKE_FLAGS}"


# prepare directory
${MKDIR} -p ${PREFIX}/lib64 ${PREFIX}/bin/x64
# remove old
${RM} -rf ${PREFIX}/lib64/libsgx_* ${PREFIX}/bin/x64/sgx_sign ${PREFIX}/sgxssl

# patch trts tcxx
echo "== Patch SDK =="
if grep -qF "char __bigger_[size()];" ${LINUX_SGX_SRC_DIR}/common/inc/sgx_random_buffers.h
then
    echo "Patching..."
    if [[ "${SDK_VER}" = "2_19" ]]
    then
        patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/sdk_2_19.patch
    elif [[ "${SDK_VER}" = "2_14" ]]
    then
        patch -p1 -d ${LINUX_SGX_SRC_DIR} < ${PATCH_DIR}/sdk_2_14.patch
    else
        echo "Unsupported SDK Version"
        exit 1
    fi
else
    echo "Already patched!"
fi

# patch dcap tvl
echo "== Patch DCAP =="
if grep -qF "COMMON_INCLUDE	:= -I\$(COMMON_DIR)/inc -I\$(COMMON_DIR)/inc/tlibc -I\$(LINUX_SDK_DIR)/tlibcxx/include" ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/dcap_tvl/Makefile
then
    echo "Patching..."
    patch -p1 -d ${LINUX_SGX_SRC_DIR}/external/dcap_source < ${PATCH_DIR}/dcap.patch
else
    echo "Already patched!"
fi

# get libsgx_trts_sim.a
echo "== Get libsgx_trts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/trtssim
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} linux/libsgx_trts_sim.a ${PREFIX}/lib64
${OBJCOPY} --redefine-sym __tls_get_addr=_deleted__tls_get_addr \
    --redefine-sym atexit=_deleted_atexit \
    --redefine-sym __cxa_atexit=_deleted__cxa_atexit \
    --redefine-sym sgx_ocall=_deleted_sgx_ocall \
    --redefine-sym get_thread_data=_deleted_get_thread_data \
    --redefine-sym sgx_is_within_enclave=_deleted_sgx_is_within_enclave \
    --redefine-sym sgx_is_outside_enclave=_deleted_sgx_is_outside_enclave \
    --redefine-sym sgx_ocalloc=_deleted_sgx_ocalloc \
    --redefine-sym sgx_ocfree=_deleted_sgx_ocfree \
    ${PREFIX}/lib64/libsgx_trts_sim.a

# get libsgx_tservice_sim.a
echo "== Get libsgx_tservice_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/tservice_sim
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} libsgx_tservice_sim.a ${PREFIX}/lib64

# get libsgx_tsafecrt.a
echo "== Get libsgx_tsafecrt.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/tsafecrt
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} libsgx_tsafecrt.a ${PREFIX}/lib64

#get libsgx_tcrypto.a
echo "== Get libsgx_tcrypto.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/tlibcrypto
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} libsgx_tcrypto.a ${PREFIX}/lib64

#get libsgx_tprotected_fs.a
echo "== Get libsgx_tprotected_fs.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/protected_fs/sgx_tprotected_fs
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} libsgx_tprotected_fs.a ${PREFIX}/lib64

#get libsgx_tkey_exchange.a
echo "== Get libsgx_tkey_exchange.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/tkey_exchange
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} libsgx_tkey_exchange.a ${PREFIX}/lib64

#get libsgx_dcap_tvl.a
echo "== Get libsgx_dcap_tvl.a =="
cd ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/dcap_tvl
${MAKE} clean -s
${MAKE} -j${Jobs} CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ADD_LLVM_FLAGS}" ${ADD_MAKE_FLAGS}
${CP} libsgx_dcap_tvl.a ${PREFIX}/lib64
${CP} ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/dcap_tvl/sgx_dcap_tvl.edl ${PREFIX}/include
${CP} ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/common/inc/{sgx_ql_lib_common,sgx_ql_quote,sgx_quote_3,sgx_quote_4}.h ${PREFIX}/include
${CP} ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/QvE/Include/sgx_qve_header.h ${PREFIX}/include

#get libsgx_ukey_exchange.a
echo "== Get libsgx_ukey_exchange.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/ukey_exchange
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} libsgx_ukey_exchange.a ${PREFIX}/lib64

#get libsgx_uprotected_fs.a
echo "== Get libsgx_uprotected_fs.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/protected_fs/sgx_uprotected_fs
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} libsgx_uprotected_fs.a ${PREFIX}/lib64

#get libsgx_urts_sim.so
echo "== Get libsgx_urts_sim.a =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/urtssim/
${MAKE} clean -s
${MAKE} ${ADD_MAKE_FLAGS}
${CP} linux/libsgx_urts_sim.so ${PREFIX}/lib64

#get {libsgx_uae_service_sim,libsgx_quote_ex_sim,libsgx_epid_sim}.so
echo "== Get {libsgx_uae_service_sim,libsgx_quote_ex_sim,libsgx_epid_sim}.so =="
cd ${LINUX_SGX_SRC_DIR}/sdk/simulation/uae_service_sim/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} {libsgx_uae_service_sim,libsgx_quote_ex_sim,libsgx_epid_sim}.so ${PREFIX}/lib64

#get libsgx_capable.{a,so}
echo "== Get libsgx_capable.{a,so} =="
cd ${LINUX_SGX_SRC_DIR}/sdk/libcapable/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} libsgx_capable.{a,so} ${PREFIX}/lib64

#get libsgx_dcap_ql.so
echo "== Get libsgx_dcap_ql.so =="
cd ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} libsgx_dcap_ql.so ${PREFIX}/lib64

#get libsgx_dcap_quoteverify.so {libsgx_dcap_qvl_attestation,libsgx_dcap_qvl_parser}.a
echo "== Get libsgx_dcap_quoteverify.so {libsgx_dcap_qvl_attestation,libsgx_dcap_qvl_parser}.a =="
cd ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/linux
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} libsgx_dcap_quoteverify.so ${PREFIX}/lib64
${CP} {libsgx_dcap_qvl_attestation,libsgx_dcap_qvl_parser}.a ${PREFIX}/lib64
cd ${PREFIX}/lib64
${LN} -sf libsgx_dcap_quoteverify.so libsgx_dcap_quoteverify.so.1

#get sgx_sign
echo "== Get sgx_sign =="
cd ${LINUX_SGX_SRC_DIR}/sdk/sign_tool/SignTool
${MAKE} clean -s
${MAKE} -j${Jobs} ${ADD_MAKE_FLAGS}
${CP} sgx_sign ${PREFIX}/bin/x64

#get intel sgxssl
echo "== Get Intel SGXSSL =="
cd ${SGXSAN_DIR}/intel-sgx-ssl
./clean.sh
./build.sh MODE=${MODE} FUZZER=${FUZZER}
${MKDIR} -p ${PREFIX}/sgxssl/
${CP} -rf ${SGXSAN_DIR}/intel-sgx-ssl/Linux/package/* ${PREFIX}/sgxssl/

cd ${PREFIX}/sgxssl/lib64

if [[ ! -f libsgx_tsgxssl.a && -f libsgx_tsgxssld.a ]]
then
    ${LN} -sf libsgx_tsgxssld.a libsgx_tsgxssl.a
fi

if [[ ! -f libsgx_tsgxssl_crypto.a && -f libsgx_tsgxssl_cryptod.a ]]
then
    ${LN} -sf libsgx_tsgxssl_cryptod.a libsgx_tsgxssl_crypto.a
fi

if [[ ! -f libsgx_usgxssl.a && -f libsgx_usgxssld.a ]]
then
    ${LN} -sf libsgx_usgxssld.a libsgx_usgxssl.a
fi

if [[ ! -f libsgx_tsgxssl_ssl.a && -f libsgx_tsgxssl_ssld.a ]]
then
    ${LN} -sf libsgx_tsgxssl_ssld.a libsgx_tsgxssl_ssl.a
fi

echo "== Successfully get SGXSDK ${MODE} =="
