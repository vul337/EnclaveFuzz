#!/bin/bash
for d in $(find . -name "profraw")
do
    ls $d|wc -l|xargs echo
done
