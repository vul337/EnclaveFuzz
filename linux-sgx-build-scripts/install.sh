#!/bin/bash
set -e

script_dir=$(realpath $(dirname $0))
linux_sgx_src_dir="$(realpath ${script_dir}/../linux-sgx)"

# install sgxsdk
sudo ${linux_sgx_src_dir}/linux/installer/bin/sgx_linux_x64_sdk_*.bin <<EOF
no
/opt/intel/
EOF

# install sgxpsw
sudo apt-get update
sudo apt-get install libsgx-launch.* libsgx-urts.* libsgx-epid.* libsgx-quote-ex.* libsgx-enclave-common.* libsgx-uae-service.* libsgx-ae-qe3.* libsgx-ae-qve.* libsgx-dcap-ql.* libsgx-dcap-default-qpl.* libsgx-dcap-quote-verify.* libsgx-ra-network.* libsgx-ra-uefi.* libsgx-qe3-logic.* -y