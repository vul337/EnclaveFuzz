#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))

BINARY_NAME=$(realpath "$1")
EXTRA_FLAG="--cb_enclave=${2} -max_len=10000000"
DIR_NAME=$(basename $(pwd))

if [[ "$DIR_NAME" == "Fuzzer2-Naive-"* ]]; then
    EXTRA_FLAG+=" --cb_naive_harness=true"
elif [[ "$DIR_NAME" == "Fuzzer2-NaiveNoOCallNoUMem-"* ]]; then
    EXTRA_FLAG+=" --cb_naive_harness=true --cb_modify_ocall_ret_prob=0 --cb_modify_double_fetch_value_prob=0"
elif [[ "$DIR_NAME" == "Fuzzer2-NoOCallNoUMem-"* ]]; then
    EXTRA_FLAG+=" --cb_modify_ocall_ret_prob=0 --cb_modify_double_fetch_value_prob=0"
elif [[ "$DIR_NAME" == "Fuzzer2-NoSan-"* ]]; then
    EXTRA_FLAG+=" --cb_enable_san_check_die=false"
elif [[ "$DIR_NAME" == "Fuzzer2-NoUMem"* ]]; then
    EXTRA_FLAG+=" --cb_modify_double_fetch_value_prob=0"
fi

${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* > ECall.log
${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* --word Try >> ECall.log
./show_cov.sh >> ECall.log

${CUR_DIR}/filter_crashes.py -b ${BINARY_NAME} -c ./result/crashes --extra-opt "${EXTRA_FLAG}"
