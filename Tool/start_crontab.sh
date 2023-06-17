#!/bin/bash
CUR_DIR=$(realpath $(dirname $0))
nohup taskset -c 0-3 ${CUR_DIR}/crontab.sh &
