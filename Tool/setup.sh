#!/bin/bash

set -e

CUR_DIR=$(realpath $(dirname $0))

show_usage() {
    echo "$(basename "$0") <FuzzBinary> <Enclave.so> <WorkDir> [TEST=0] [TASKSET=\"taskset -c 0\"]"
    exit 1
}

# Print Help
if [ $# -lt 3 ]; then show_usage; fi

# BASIC ARG
BINARY_PATH=$(realpath "$1")
ENCLAVE_PATH=$(realpath "$2")
WORKDIR="$3"
shift 3

for ARG in "$@"
do
   KEY="$(echo ${ARG} | cut -f1 -d=)"
   VAL="$(echo ${ARG} | cut -f2 -d=)"
   export "${KEY}"="${VAL}"
done

TEST=${TEST:="0"}
TASKSET=${TASKSET:=""}
BINARY_NAME=$(basename ${BINARY_PATH})
ENCLAVE_NAME=$(basename ${ENCLAVE_PATH})
EVAL_TOP="${WORKDIR}-T${TEST}-$(date +%F)"

echo "-- BINARY_PATH: ${BINARY_PATH}"
echo "-- ENCLAVE_PATH: ${ENCLAVE_PATH}"
echo "-- TEST: ${TEST}"
echo "-- TASKSET: ${TASKSET}"
echo "-- BINARY_NAME: ${BINARY_NAME}"
echo "-- ENCLAVE_NAME: ${ENCLAVE_NAME}"
echo "-- EVAL_TOP: ${EVAL_TOP}"

echo "Create WorkDir"
mkdir -p "${EVAL_TOP}"
mkdir -p "${EVAL_TOP}/result/seeds"
mkdir -p "${EVAL_TOP}/result/crashes"
mkdir -p "${EVAL_TOP}/result/profraw"
# REAL_PROF_DIR=$(dirname "$(dirname "${EVAL_TOP}")")/RAMDISK/$(basename "$(dirname "${EVAL_TOP}")")/$(basename "${EVAL_TOP}")
# echo "-- REAL_PROF_DIR=${REAL_PROF_DIR}"
# mkdir -p ${REAL_PROF_DIR}
# rm -rf ${EVAL_TOP}/result/profraw
# ln -sf ${REAL_PROF_DIR} ${EVAL_TOP}/result/profraw

cd ${EVAL_TOP}

echo "Copy Files"
cp -i ${BINARY_PATH} ${BINARY_NAME}
cp -i ${ENCLAVE_PATH} ${ENCLAVE_NAME}

echo "Create show_cov.sh"
cat > show_cov.sh <<EOF
#!/usr/bin/env bash
set -e

# llvm-profdata-13 merge --failure-mode=all -sparse -output=./result/all.profdata ./result/profraw/
llvm-cov-13 report ./${ENCLAVE_NAME} -instr-profile=./result/all.profdata
EOF
chmod +x show_cov.sh

echo "Create fuzz.sh"
cat > fuzz.sh <<EOF
#!/usr/bin/env bash
set -e

CUR_DIR=\$(realpath .)
echo "TMPDIR=\${CUR_DIR}"
TMPDIR=\${CUR_DIR} LLVM_PROFILE_FILE="./result/profraw/%p" ${TASKSET} nohup ./${BINARY_NAME} --cb_enclave=${ENCLAVE_NAME} ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 -timeout=60 -max_total_time=86400 -fork=1 \$@ >> coverage_exp.log 2>&1 & 
echo \$! >> fuzz.pid
echo "TMPDIR=\${CUR_DIR} LLVM_PROFILE_FILE=\"./result/profraw/%p\" ${TASKSET} nohup ./${BINARY_NAME} --cb_enclave=${ENCLAVE_NAME} ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 -timeout=60 -max_total_time=86400 -fork=1 \$@" >> fuzz.cmd
echo "--cb_enclave=${ENCLAVE_NAME} -max_len=10000000 \$@" >> debug.extra.cmd
echo "${BINARY_NAME}" >> binary.name
nohup ./merge.sh &
echo \$! >> merge.pid
echo \$(date +%Y\_%m\_%d\_%H\_%M\_%S) >> StartTime.log
EOF
chmod +x fuzz.sh

echo "Copy stop.sh"
cp ${CUR_DIR}/workdir/stop.sh ${EVAL_TOP}

echo "Copy merge.sh"
cp ${CUR_DIR}/workdir/merge.sh ${EVAL_TOP}













