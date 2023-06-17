#!/usr/bin/env bash
set -e

CUR_DIR=$(realpath $(dirname $0))
OUTPUT_FILENAME=${CUR_DIR}/result/all.profdata

# Reads the paths to prof data files from INPUT_FILENAME and then merges them into OUTPUT_FILENAME.
TARGETS=($(find $(realpath ${CUR_DIR}/result/profraw) -type f -printf "%T@\t%Tc %6k KiB %p\n" | sort -n | tr -s ' ' | cut -d ' ' -f 6 | head -n -5))

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "Error! No *.profraw targets to merge!"
    exit 1
fi

echo "New profdata ${#TARGETS[@]}"

if [ -f "$OUTPUT_FILENAME" ]; then
    echo "$OUTPUT_FILENAME exists."
    for t in "${TARGETS[@]}"; do
        if llvm-profdata-13 merge -o=${OUTPUT_FILENAME}.tmp ${t} ${OUTPUT_FILENAME}; then
            mv ${OUTPUT_FILENAME}.tmp ${OUTPUT_FILENAME}
        fi
        rm ${t}
    done
else
    echo "$OUTPUT_FILENAME does not exist."
    FIRST_TARGET=${TARGETS[0]}
    llvm-profdata-13 merge -sparse -o=${OUTPUT_FILENAME} ${FIRST_TARGET}
    for t in "${TARGETS[@]:1}"; do
        if llvm-profdata-13 merge -o=${OUTPUT_FILENAME}.tmp ${t} ${OUTPUT_FILENAME}; then
            mv ${OUTPUT_FILENAME}.tmp ${OUTPUT_FILENAME}
        fi
        rm ${t}
    done
fi

wait

