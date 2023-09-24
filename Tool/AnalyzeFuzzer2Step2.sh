#!/bin/bash
set -e

OUTPUT=$1

echo -en "Success Rate:\t\t\t" > ${OUTPUT}
SumEnter=$(cat ECall.log|grep Enter|cut -d " " -f1|awk '{sum +=$1};END {print sum}')
SumTry=$(cat ECall.log|grep Try|cut -d " " -f1|awk '{sum +=$1};END {print sum}')
awk -v var1=$SumEnter -v var2=$SumTry 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${OUTPUT}

# Cov info
CovInfo=$(cat ECall.log|grep -v "Try"|grep -v "Enter"|grep -v Filename|grep -v TOTAL|grep -v "\-\-\-\-\-"|grep -v "Files which contain no functions"|grep -v "^$"|tr -s " ")
read -r AllBB CovBB <<< $(echo "${CovInfo}"|awk '{ col2_sum += $2; col3_sum += $3 } END { printf "%d %d", col2_sum, col2_sum-col3_sum }')
read -r DevAllBB DevCovBB <<< $(echo "${CovInfo}"|grep -v "_t[.]c"|grep -v "_t[.]h"|grep -Pv 'linux-sgx(?!/psw/ae)'|awk '{ col2_sum += $2; col3_sum += $3 } END { printf "%d %d", col2_sum, col2_sum-col3_sum }')

echo -en "EnclaveCoverage:\t\t" >> ${OUTPUT}
awk -v var1=$CovBB -v var2=$AllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${OUTPUT}

echo -en "InterestingCoverage:\t" >> ${OUTPUT}
awk -v var1=$DevCovBB -v var2=$DevAllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${OUTPUT}

echo -en "Effectiveness:\t\t\t" >> ${OUTPUT}
awk -v var1=$DevCovBB -v var2=$CovBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${OUTPUT}
