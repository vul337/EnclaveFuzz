#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))

BINARY_NAME=$(realpath "$1")
ENCLAVE_NAME=$(realpath "$2")

${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* > ECall.log
${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* --kind Try >> ECall.log
./show_cov.sh >> ECall.log
${CUR_DIR}/filter_crashes.py -b ${BINARY_NAME} -c ./result/crashes --extra-opt "--cb_enclave=${ENCLAVE_NAME} -max_len=10000000"
