#!/bin/bash

CUR_DIR=$(realpath $(dirname $0))
WORK_DIR=$(realpath .)
# BINARY_NAME="$1"
# ENCLAVE_NAME="$2"

for dir in $(ls | grep Fuzzer1 | grep -v "Result")
do
#     Assue directory is like:
#     EnclaveApp      
#       Fuzzer2-NaiveNoOCallNoUMem-T0-2023-06-26
#       Fuzzer2-Naive-T0-2023-06-26
#       Fuzzer2-NoOCallNoUMem-T0-2023-06-26
#       Fuzzer2-NoSan-T0-2023-06-26
#       Fuzzer2-T0-2023-06-26
    # EXTRA_FLAG="--cb_enclave=${ENCLAVE_NAME} -max_len=10000000"
    cd ${WORK_DIR}/${dir}
    echo ${WORK_DIR}/${dir}
    # if [[ "$dir" == "Fuzzer2-Naive-"* ]]; then
    #     EXTRA_FLAG+=" --cb_naive_harness=true"
    # elif [[ "$dir" == "Fuzzer2-NaiveNoOCallNoUMem-"* ]]; then
    #     EXTRA_FLAG+=" --cb_naive_harness=true --cb_modify_ocall_ret_prob=0 --cb_modify_double_fetch_value_prob=0"
    # elif [[ "$dir" == "Fuzzer2-NoOCallNoUMem-"* ]]; then
    #     EXTRA_FLAG+=" --cb_modify_ocall_ret_prob=0 --cb_modify_double_fetch_value_prob=0"
    # elif [[ "$dir" == "Fuzzer2-NoSan-"* ]]; then
    #     EXTRA_FLAG+=" --cb_enable_san_check_die=false"
    # fi
    # echo ${EXTRA_FLAG}
    # nohup ${CUR_DIR}/AnalyzeFuzzer2Step1.sh ${BINARY_NAME} ${EXTRA_FLAG} &
    nohup ${CUR_DIR}/AnalyzeFuzzer1Step1.sh &
done
