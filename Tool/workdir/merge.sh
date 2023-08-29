#!/bin/bash
set -e

TARGET_DIR=$(realpath $(dirname $0))
ALL_PROFDATA=${TARGET_DIR}/result/all.profdata

merge_cov() {
    # Reads the paths to prof data files from INPUT_FILENAME and then merges them into ALL_PROFDATA.
    PROFRAWS=($(find $(realpath ${TARGET_DIR}/result/profraw) -type f -printf "%T@\t%Tc %6k KiB %p\n" | sort -n | tr -s ' ' | cut -d ' ' -f 6 | head -n -1))

    if [[ ${#PROFRAWS[@]} -ne 0 ]]; then
        echo "${#PROFRAWS[@]} new profraw"

        if [ ! -f "$ALL_PROFDATA" ]; then
            if llvm-profdata-13 merge -sparse -o=${ALL_PROFDATA} ${PROFRAWS[0]}; then
                echo "Create ${ALL_PROFDATA}"
            else
                echo "Wrong profraw: ${PROFRAWS[0]}"
            fi
            rm ${PROFRAWS[0]}
            unset PROFRAWS[0]
        fi
        for raw in "${PROFRAWS[@]}"; do
            if llvm-profdata-13 merge -sparse -o=${ALL_PROFDATA}.tmp ${raw} ${ALL_PROFDATA}; then
                mv ${ALL_PROFDATA}.tmp ${ALL_PROFDATA}
            else
                echo "Wrong profraw: ${raw}"
            fi
            rm ${raw}
        done
    else
        echo "No profraw file to merge"
    fi
}

parse_cov() {
    mkdir -p ${TARGET_DIR}/coverage
    LOG_FILE="${TARGET_DIR}/coverage/cov_$(date +%Y\_%m\_%d\_%H\_%M\_%S)"
    COV_INFO=$(${TARGET_DIR}/show_cov.sh|grep -v Filename|grep -v TOTAL|grep -v "\-\-\-\-\-"|grep -v "Files which contain no functions"|grep -v "^$"|tr -s " ")
    read -r AllBB CovBB <<< $(echo "${COV_INFO}"|awk '{ col2_sum += $2; col3_sum += $3 } END { printf "%d %d", col2_sum, col2_sum-col3_sum }')
    read -r DevAllBB DevCovBB <<< $(echo "${COV_INFO}"|grep -v "_t[.]c"|grep -v "_t[.]h"|grep -v "linux-sgx/"|awk '{ col2_sum += $2; col3_sum += $3 } END { printf "%d %d", col2_sum, col2_sum-col3_sum }')

    if [ ${AllBB} -gt 0 ]; then
        echo -en "EnclaveCoverage:\t\t" > ${LOG_FILE}
        awk -v var1=$CovBB -v var2=$AllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${LOG_FILE}
    fi

    if [ ${DevAllBB} -gt 0 ]; then
        echo -en "InterestingCoverage:\t" >> ${LOG_FILE}
        awk -v var1=$DevCovBB -v var2=$DevAllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${LOG_FILE}
    fi

    if [ ${CovBB} -gt 0 ]; then
        echo -en "Effectiveness:\t\t\t" >> ${LOG_FILE}
        awk -v var1=$DevCovBB -v var2=$CovBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${LOG_FILE}
    fi
}

while true
do
    merge_cov
    if [ -f "$ALL_PROFDATA" ]; then
        parse_cov
    fi
    sleep 10
done
