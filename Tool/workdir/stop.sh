#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))
echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) >> StopTime.log
for i in $(cat ${CUR_DIR}/fuzz.pid)
do
    echo "Kill ${i}"
    kill -9 ${i} || true
done

for i in $(cat ${CUR_DIR}/merge.pid)
do
    echo "Kill ${i}"
    kill -9 ${i} || true
done
