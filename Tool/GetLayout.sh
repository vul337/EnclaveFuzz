#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
GHIDRA_DIR=$(realpath ${SCRIPT_DIR}/../kAFL/kafl/ghidra_10.1.3_PUBLIC)
CUR_DIR=$(pwd)
WORK_DIR=${CUR_DIR}/ghidra
OBJECT_DIR=${CUR_DIR}

function PrintHelp() {
    echo "GetLayout.sh [-d OBJECT_DIR] [OBJECT, ...]"
}

while getopts "d:h" opt
do
    case $opt in
        d)
            OBJECT_DIR=${OPTARG}
            ;;
        h|?)
            PrintHelp
            exit 1
            ;;
    esac
done
shift $(($OPTIND - 1))

mkdir -p ${WORK_DIR}

for ARG in "$@"
do
    if [[ "$ARG" = /* ]]
    then
        OBJ=${ARG}
    else
        OBJ=$(realpath ${OBJECT_DIR}/${ARG})
    fi

    if [[ ! -f ${OBJ} ]]
    then
        echo "Bad OBJECT_DIR for ${OBJ}"
        PrintHelp
        exit 1
    fi

    if [[ "$(file ${OBJ})" =~ "current ar archive" ]]
    then
        AR_DIR=$(realpath ${WORK_DIR}/$(echo $(basename ${OBJ})|sed "s@\.@_@g"))
        mkdir -p ${AR_DIR}
        ar -x ${OBJ} --output ${AR_DIR}
        AR_DIRS[${#AR_DIRS[@]}]=${AR_DIR}
    else
        OBJS[${#OBJS[@]}]=${OBJ}
    fi
done

echo "== Importing =="
${GHIDRA_DIR}/support/analyzeHeadless ${WORK_DIR} sym_analysis -max-cpu $(nproc) -import ${OBJS[@]} ${AR_DIRS[@]} &>> ${WORK_DIR}/run.log

echo "== Analyzing =="
${GHIDRA_DIR}/support/analyzeHeadless ${WORK_DIR} sym_analysis -max-cpu $(nproc) -noanalysis -process -recursive -scriptPath ${SCRIPT_DIR} -postscript GetLayout.py +o ${WORK_DIR}/layout_tmp &>> ${WORK_DIR}/run.log

echo "== Merging =="
jq -s 'reduce .[] as $item ({}; . * $item)' ${WORK_DIR}/layout_tmp/* > ${WORK_DIR}/layout.json
