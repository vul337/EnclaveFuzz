#!/bin/bash

set -e

# Print Help
if [[ "$1" == "-h" ]] || [ $# -ne 4 ]; then
    echo "$(basename "$0") <fuzzbin> <enclave.so> WorkDir ID"
    exit 0
fi

# ARG
SRC_FUZZERBIN=$(realpath -s "$1")
SRC_ENCLAVEBIN=$(realpath -s "$2")
WORKDIR=$(realpath -s "$3")
TEST=$4

FUZZERNAME=$(basename ${SRC_FUZZERBIN})
ENCLAVENAME=$(basename ${SRC_ENCLAVEBIN})

EVALTOP="$WORKDIR-T$TEST-$(date +%F)"

# Make Dir
mkdir -p $EVALTOP
mkdir -p "$EVALTOP/result/seeds"
mkdir -p "$EVALTOP/result/crashes"
mkdir -p "$EVALTOP/result/profraw"

# Copy
echo "[SRC] Fuzzing Binary: $SRC_FUZZERBIN"
echo "[SRC] Enclave Binary: $SRC_ENCLAVEBIN"
echo "Evaluation Directory: $EVALTOP"
echo "[DST] Fuzzing Binary: $EVALTOP/$FUZZERNAME"
echo "[DST] Enclave Binary: $EVALTOP/$ENCLAVENAME"

cp $SRC_FUZZERBIN $EVALTOP/$FUZZERNAME
cp $SRC_ENCLAVEBIN $EVALTOP/$ENCLAVENAME

cd $EVALTOP
# echo ""
# echo "LLVM_PROFILE_FILE=\"./result/profraw/%p\" ./$FUZZERNAME --cb_enclave=$ENCLAVENAME ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -fork=1 "

# Create show_cov.sh
cat > show_cov.sh <<EOF
#!/usr/bin/env bash

# llvm-profdata-13 merge --failure-mode=all -sparse -output=./result/all.profdata ./result/profraw/
llvm-cov-13 report ./$ENCLAVENAME -instr-profile=./result/all.profdata

EOF
chmod +x show_cov.sh

# Create fuzz.sh
cat > fuzz.sh <<EOF
#!/usr/bin/env bash

set -ex

LLVM_PROFILE_FILE="./result/profraw/%p" nohup ./$FUZZERNAME --cb_enclave=$ENCLAVENAME ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 \$@ >> coverage_exp.log 2>&1 & 
fuzz_pid=\$!
echo \$fuzz_pid > fuzz.pid
echo "./$FUZZERNAME --cb_enclave=$ENCLAVENAME ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 \$@" >> fuzz.cmd
ln -sf /tmp/libFuzzerTemp.FuzzWithFork\$fuzz_pid.dir ./libFuzzerTemp
# tail -f coverage_exp.log
EOF
chmod +x fuzz.sh

# Create stop.sh
cat > stop.sh <<EOF
#!/usr/bin/env bash

set -ex

kill -9 \$(cat fuzz.pid)
rm fuzz.pid
EOF
chmod +x stop.sh

# Create merge.sh
cat > merge.sh <<EOF
#!/usr/bin/env bash

set +x
set +e

# PROFRAW_DIR=\$1
OUTPUT_FILENAME=./result/all.profdata

# Reads the paths to prof data files from INPUT_FILENAME and then merges them
# into OUTPUT_FILENAME.
#TARGETS=(\$(find ./result/profraw -type f))
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













