#!/bin/bash

set -e

show_usage() {
    echo "$(basename "$0") <FuzzBinary> <Enclave.so> <WorkDir> [TEST=0] [TASKSET=\"taskset -c 0\"]"
    exit 1
}

# Print Help
if [ $# -lt 3 ]; then show_usage; fi

# BASIC ARG
BINARY_PATH=$(realpath "$1")
ENCLAVE_PATH=$(realpath "$2")
WORKDIR=$(realpath "$3")
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
TMPDIR=\${CUR_DIR} LLVM_PROFILE_FILE="./result/profraw/%p" ${TASKSET} nohup ./${BINARY_NAME} --cb_enclave=${ENCLAVE_NAME} ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 \$@ >> coverage_exp.log 2>&1 & 
fuzz_pid=\$!
echo \$fuzz_pid >> fuzz.pid
echo "TMPDIR=\${CUR_DIR} LLVM_PROFILE_FILE=\"./result/profraw/%p\" ${TASKSET} nohup ./${BINARY_NAME} --cb_enclave=${ENCLAVE_NAME} ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 \$@" >> fuzz.cmd
# tail -f coverage_exp.log
EOF
chmod +x fuzz.sh

echo "Create stop.sh"
cat > stop.sh <<EOF
#!/usr/bin/env bash
set -e

for i in \$(cat fuzz.pid)
do
    echo "Kill \${i}"
    kill -9 \${i} || echo ""
done
EOF
chmod +x stop.sh

# Create merge.sh
cat > merge.sh <<EOF
#!/usr/bin/env bash
set -e

OUTPUT_FILENAME=./result/all.profdata

# Reads the paths to prof data files from INPUT_FILENAME and then merges them into OUTPUT_FILENAME.
TARGETS=(\$(find ./result/profraw -type f -printf "%T@\t%Tc %6k KiB %p\n" | sort -n | tr -s ' ' | cut -d ' ' -f 6 | head -n -5))

if [[ \${#TARGETS[@]} -eq 0 ]]; then
    echo "Error! No *.profraw targets to merge!"
    exit 1
fi

echo "New profdata \${#TARGETS[@]}"

if [ -f "\$OUTPUT_FILENAME" ]; then
    echo "\$OUTPUT_FILENAME exists."
    for t in "\${TARGETS[@]}"; do
        echo "Merge \$t"
        llvm-profdata-13 merge -j=1 -o=\${OUTPUT_FILENAME}.tmp \${t} \${OUTPUT_FILENAME}
        mv \${OUTPUT_FILENAME}.tmp \${OUTPUT_FILENAME}
        rm \${t}
    done
else
    echo "\$OUTPUT_FILENAME does not exist."
    echo "\$TARGETS"
    FIRST_TARGET=\${TARGETS[0]}
    llvm-profdata-13 merge -sparse -output=\${OUTPUT_FILENAME} \${FIRST_TARGET}
    for t in "\${TARGETS[@]:1}"; do
        echo "Merge \$t"
        llvm-profdata-13 merge -j=1 -o=\${OUTPUT_FILENAME}.tmp \${t} \${OUTPUT_FILENAME}
        mv \${OUTPUT_FILENAME}.tmp \${OUTPUT_FILENAME}
        rm \${t}
    done
fi

wait

EOF
chmod +x merge.sh













