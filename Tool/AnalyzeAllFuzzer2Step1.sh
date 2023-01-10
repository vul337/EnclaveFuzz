#!/bin/bash

CUR_DIR=$(realpath $(dirname $0))
WORK_DIR=$(realpath .)
BINARY_NAME="$1"
ENCLAVE_NAME="$2"

for dir in $(ls | grep Fuzzer2 | grep -v "Result")
do
    cd ${WORK_DIR}/${dir}
    ${CUR_DIR}/AnalyzeFuzzer2Step1.sh ${BINARY_NAME} ${ENCLAVE_NAME}
done
