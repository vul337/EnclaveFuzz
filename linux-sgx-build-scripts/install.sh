#!/bin/bash
set -e

script_dir=$(realpath -s $(dirname $0))
linux_sgx_src_dir="$(realpath -s ${script_dir}/../linux-sgx)"

sudo apt-get install build-essential python -y

# install sgxsdk
cd ${linux_sgx_src_dir}/linux/installer/bin
sudo ./sgx_linux_x64_sdk_*.bin <<EOF
no
/opt/intel/
EOF

# install sgxpsw
sudo apt-get update
sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev -y
cd ${linux_sgx_src_dir}/linux/installer/deb
sudo dpkg -i libsgx-urts_* libsgx-enclave-common_*
sudo dpkg -i libsgx-enclave-common-dev_*
sudo dpkg -i libsgx-enclave-common-dbgsym_*