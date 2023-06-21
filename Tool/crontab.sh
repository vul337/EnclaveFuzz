#!/bin/bash

always_run() {
    while true
    do
        echo "Run $1"
        $1
        sleep 5
    done
}

for f in $(find . -name "merge.sh")
do
    always_run ${f} &
done
