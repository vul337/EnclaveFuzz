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

# Only uncomment when reboot
# if [[ -r "\${SGXFUZZ_ROOT}/kvm-nyx-release/kvm-intel.ko" ]]; then
# 	sudo rmmod kvm_intel || true
# 	sudo rmmod kvm || true
# 	sudo insmod "\${SGXFUZZ_ROOT}/kvm-nyx-release/kvm.ko" || true
# 	sudo insmod "\${SGXFUZZ_ROOT}/kvm-nyx-release/kvm-intel.ko" || true
# 	sudo chmod a+rw /dev/kvm
# fi

# Build the enclave runner
\${SGXFUZZ_ROOT}/initialize-target.sh ${NAME} ${ENCLAVE_PATH}.mem \$1 \$2

echo "-- CPU Offset: \$1"
echo "-- TEST ID: \$2"

cd "\$(ls -d ${NAME}-\$2-T0-\$(date +%F)*/ | sort -r | head -1)"

./pack.sh

# Generate ghidra project before fuzz
mkdir -p ./sgx_workdir/traces
source ${SGXSAN_DIR}/kAFL/kafl/env.sh
${SGXSAN_DIR}/kAFL/kafl/fuzzer/scripts/ghidra_run.sh \$(realpath ./sgx_workdir) ${ENCLAVE_PATH} ${SGXSAN_DIR}/kAFLUSpaceUtil/ghidra_cov_analysis_sgxfuzz.py &> /dev/null

nohup ./fuzz.sh &> /dev/null &
echo \$! > fuzz.pid
echo \$(date +%Y\_%m\_%d\_%H\_%M\_%S) > StartTime.log

nohup bash -c "while true; do ${SGXSAN_DIR}/kAFL/kafl/fuzzer/scripts/ghidra_run.sh \$(realpath ./sgx_workdir) ${ENCLAVE_PATH} ${SGXSAN_DIR}/kAFLUSpaceUtil/ghidra_cov_analysis_sgxfuzz.py &> /dev/null; done" &
echo \$! > cov.pid

EOF
chmod +x run-${NAME}.sh
