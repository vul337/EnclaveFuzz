#!/bin/bash
while true
do
    for f in $(find . -name "merge.sh")
    do
        ${f} &
    done
    wait
    sleep 3
done
