#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))

${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* > ECall.log
${CUR_DIR}/CountEnterECall.py libFuzzerTemp.FuzzWithFork* --word Try >> ECall.log
