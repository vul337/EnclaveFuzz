#!/usr/bin/env bash
set -e

CUR_DIR=$(realpath $(dirname $0))
OUTPUT_FILENAME=${CUR_DIR}/result/all.profdata

# Reads the paths to prof data files from INPUT_FILENAME and then merges them into OUTPUT_FILENAME.
TARGETS=($(find ${CUR_DIR}/result/profraw -type f -printf "%T@\t%Tc %6k KiB %p\n" | sort -n | tr -s ' ' | cut -d ' ' -f 6 | head -n -5))

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "Error! No *.profraw targets to merge!"
    exit 1
fi

echo "New profdata ${#TARGETS[@]}"

if [ -f "$OUTPUT_FILENAME" ]; then
    echo "$OUTPUT_FILENAME exists."
    for t in "${TARGETS[@]}"; do
        if llvm-profdata-13 merge -j=1 -o=${OUTPUT_FILENAME}.tmp ${t} ${OUTPUT_FILENAME}; then
            echo "Merge $t"
            mv ${OUTPUT_FILENAME}.tmp ${OUTPUT_FILENAME}
            rm ${t}
        else
            echo "Merge $t Fail"
        fi
    done
else
    echo "$OUTPUT_FILENAME does not exist."
    echo "$TARGETS"
    FIRST_TARGET=${TARGETS[0]}
    llvm-profdata-13 merge -sparse -output=${OUTPUT_FILENAME} ${FIRST_TARGET}
    for t in "${TARGETS[@]:1}"; do
        if llvm-profdata-13 merge -j=1 -o=${OUTPUT_FILENAME}.tmp ${t} ${OUTPUT_FILENAME}; then
            echo "Merge $t"
            mv ${OUTPUT_FILENAME}.tmp ${OUTPUT_FILENAME}
            rm ${t}
        else
            echo "Merge $t Fail"
        fi
    done
fi

wait

