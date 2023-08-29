#!/bin/bash
set -e

INPUT_FILE=$(realpath $1)

# Cov info
CovInfo=$(cat ${INPUT_FILE}|grep -v "Blocks"|tr -s " ")
read -r CovBB AllBB <<< $(echo "${CovInfo}"|awk -F, '{ col1_sum += $1; col2_sum += $2 } END { printf "%d %d", col1_sum, col2_sum }')
read -r DevCovBB DevAllBB <<< $(echo "${CovInfo}"|grep -v "_t[.]o"|grep -v "/opt/intel/sgxsdk"|awk -F, '{ col1_sum += $1; col2_sum += $2 } END { printf "%d %d", col1_sum, col2_sum }')

echo -en "EnclaveCoverage:\t\t"
awk -v var1=$CovBB -v var2=$AllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }'

echo -en "InterestingCoverage:\t\t"
awk -v var1=$DevCovBB -v var2=$DevAllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }'

echo -en "Effectiveness:\t\t\t"
awk -v var1=$DevCovBB -v var2=$CovBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }'
