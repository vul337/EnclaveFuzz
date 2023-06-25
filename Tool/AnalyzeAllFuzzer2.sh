#!/bin/bash

CUR_DIR=$(realpath $(dirname $0))
WORK_DIR=$(realpath .)
BINARY_NAME="$1"
ENCLAVE_NAME="$2"

for dir in $(ls | grep Fuzzer2)
do
    cd ${WORK_DIR}/${dir}
    echo ${WORK_DIR}/${dir}
    nohup ${CUR_DIR}/AnalyzeFuzzer2.sh ${BINARY_NAME} ${ENCLAVE_NAME} &
done
