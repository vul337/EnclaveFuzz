#!/bin/bash

CUR_DIR=$(realpath $(dirname $0))
WORK_DIR=$(realpath .)

for dir in $(ls | grep Fuzzer2 | grep -v "Result")
do
    cd ${WORK_DIR}/${dir}
    echo "${WORK_DIR}/${dir}"
    ${CUR_DIR}/AnalyzeFuzzer2Step2.sh ${WORK_DIR}/Result_${dir}.txt
done
