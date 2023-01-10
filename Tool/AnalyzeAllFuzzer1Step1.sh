#!/bin/bash

CUR_DIR=$(realpath $(dirname $0))
WORK_DIR=$(realpath .)

for dir in $(ls | grep Fuzzer1 | grep -v "Result")
do
    cd ${WORK_DIR}/${dir}
    ${CUR_DIR}/AnalyzeFuzzer1Step1.sh
done
