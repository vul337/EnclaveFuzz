#!/bin/bash

# set -ex

if [[ " $*" == *" -h"* ]]; then
    echo "$(basename "$0") <fuzzbin> <enclave.so> Name ID"
    exit 0
fi
if [ $# -ne 4 ]; then
     echo "Illegal number of parameters"
     exit 0
fi

BASE=$(realpath ./)

FUZZERNAME=$1
ENCLAVENAME=$2
NAME=$3
TEST=$4


FUZZERBIN=$(realpath "$BASE/$FUZZERNAME")
ENCLAVEBIN=$(realpath "$BASE/$ENCLAVENAME")


EVALTOP="$BASE/$NAME-T$TEST-$(date +%F)"
SEEDS="$EVALTOP/result/seeds"
CRASHES="$EVALTOP/result/crashes"
PROFILE="$EVALTOP/result/profraw"

mkdir -p $EVALTOP
mkdir -p $SEEDS
mkdir -p $CRASHES
mkdir -p $PROFILE


echo "Use fuzzing binary: $FUZZERNAME, enclave binary: $ENCLAVENAME"
echo "Fuzzing binary: $FUZZERBIN, enclave binary: $ENCLAVEBIN"
echo "Evaluation directory: $EVALTOP"


cp $FUZZERBIN $EVALTOP/$FUZZERNAME
cp $ENCLAVEBIN $EVALTOP/$ENCLAVENAME

cd $EVALTOP
# echo ""
# echo "LLVM_PROFILE_FILE=\"./result/profraw/%p\" ./$FUZZERNAME --cb_enclave=$ENCLAVENAME ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -fork=1 "


cat > show_cov.sh <<EOF
#!/usr/bin/env bash

llvm-profdata-13 merge -sparse -output=./result/all.profdata ./result/profraw/
llvm-cov-13 report ./$ENCLAVENAME -instr-profile=./result/all.profdata -use-color

EOF
chmod +x show_cov.sh


cat > fuzz.sh <<EOF
#!/usr/bin/env bash

set -ex

LLVM_PROFILE_FILE="./result/profraw/%p" nohup ./$FUZZERNAME --cb_enclave=$ENCLAVENAME ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ \$@ >> coverage_exp.log 2>&1 & 
fuzz_pid=\$!
echo \$fuzz_pid > fuzz.pid
echo "./$FUZZERNAME --cb_enclave=$ENCLAVENAME ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ \$@" >> fuzz.cmd
ln -s /tmp/libFuzzerTemp.FuzzWithFork\$fuzz_pid.dir ./libFuzzerTemp
tail -f coverage_exp.log
EOF
chmod +x fuzz.sh

cat > stop.sh <<EOF
#!/usr/bin/env bash

set -ex

kill -9 \$(cat fuzz.pid)
rm fuzz.pid
EOF
chmod +x stop.sh















