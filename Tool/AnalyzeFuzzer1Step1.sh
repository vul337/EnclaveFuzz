#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))

# BINARY_NAME=$(realpath "$1")
# EXTRA_FLAG="${@:2}"

${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* > ECall.log
${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* --kind Try >> ECall.log

# echo "${CUR_DIR}/filter_crashes.py -b ${BINARY_NAME} -c ./result/crashes --extra-opt \"${EXTRA_FLAG}\""
# ${CUR_DIR}/filter_crashes.py -b ${BINARY_NAME} -c ./result/crashes --extra-opt "${EXTRA_FLAG}"
