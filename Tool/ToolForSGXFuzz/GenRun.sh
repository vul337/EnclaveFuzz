#!/bin/bash

set -e

# BASIC ARG
RUN_DIR=$(pwd)
SCRIPT_DIR=$(realpath $(dirname $0))
SGXSAN_DIR=$(dirname $(dirname ${SCRIPT_DIR}))
SGXFUZZ_ROOT=$(realpath $1)
ENCLAVE_PATH=$(realpath "$2")
NAME="$3"

echo "Create run-${NAME}.sh"
cat > run-${NAME}.sh <<EOF
#!/bin/bash
set -e

SGXFUZZ_ROOT=${SGXFUZZ_ROOT}
ENCLAVE_PATH=$(dirname ${ENCLAVE_PATH})
FUZZ_FOLDER=/tmp/sgxfuzz-fuzz-folder
FUZZ_WORKDIR=/tmp/sgxfuzz-workdir

if [[ ! -d "\${SGXFUZZ_ROOT}/native-sgx-runner" ]]; then
	echo "Invalid execution directory"
	exit 1
fi

# Build the enclave runner
\${SGXFUZZ_ROOT}/initialize-target.sh ${NAME} ${ENCLAVE_PATH}.mem \$1 \$2

echo "-- CPU Offset: \$1"
echo "-- TEST ID: \$2"

cd "\$(ls -d ${NAME}-\$2-T0-\$(date +%F)*/ | sort -r | head -1)"

./pack.sh

# Generate ghidra project before fuzz
mkdir -p log
mkdir -p ./sgx_workdir/traces
source ${SGXSAN_DIR}/kAFL/kafl/env.sh
${SGXSAN_DIR}/kAFLUSpaceUtil/ghidra_run.sh \$(realpath ./sgx_workdir) ${ENCLAVE_PATH} ${SGXSAN_DIR}/kAFLUSpaceUtil/ghidra_cov_analysis.py ++base_addr=0x555555654000 ++dump_dir=./coverage ++layout $(dirname ${ENCLAVE_PATH})/ghidra/layout.json ++edge_file \$(realpath ./sgx_workdir/traces/edges_uniq.lst) &> log/\$(date +%Y\_%m\_%d\_%H\_%M\_%S)

nohup ./fuzz.sh &> /dev/null &
echo \$! > fuzz.pid
echo \$(date +%Y\_%m\_%d\_%H\_%M\_%S) > StartTime.log

nohup bash -c "while true; do ${SGXSAN_DIR}/kAFLUSpaceUtil/ghidra_run.sh \$(realpath ./sgx_workdir) ${ENCLAVE_PATH} ${SGXSAN_DIR}/kAFLUSpaceUtil/ghidra_cov_analysis.py ++base_addr=0x555555654000 ++dump_dir=./coverage ++layout $(dirname ${ENCLAVE_PATH})/ghidra/layout.json ++edge_file \$(realpath ./sgx_workdir/traces/edges_uniq.lst) &> log/\\\$(date +%Y\_%m\_%d\_%H\_%M\_%S); done" &
echo \$! > cov.pid

EOF
chmod +x run-${NAME}.sh
