#!/bin/bash

CUR_DIR=$(realpath $(dirname $0))
WORK_DIR=$(realpath .)

for dir in $(ls | grep Fuzzer1 | grep -v "Result")
do
    cd ${WORK_DIR}/${dir}
    ${CUR_DIR}/AnalyzeFuzzer1Step2.sh ${WORK_DIR}/Result_${dir}.txt
done
