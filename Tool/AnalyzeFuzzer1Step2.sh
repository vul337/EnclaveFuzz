#!/bin/bash
set -e

OUTPUT=$1

echo -en "Success Rate:\t\t\t" > ${OUTPUT}
SumEnter=$(cat ECall.log|grep Enter|cut -d " " -f1|awk '{sum +=$1};END {print sum}')
SumTry=$(cat ECall.log|grep Try|cut -d " " -f1|awk '{sum +=$1};END {print sum}')
awk -v var1=$SumEnter -v var2=$SumTry 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${OUTPUT}
