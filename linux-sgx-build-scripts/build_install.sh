#!/bin/bash
set -e

script_dir=$(realpath $(dirname $0))
linux_sgx_src_dir="$(realpath ${script_dir}/../linux-sgx)"

sudo pwd
FLAGS="$@"

cd ${linux_sgx_src_dir}

# build sgxsdk
# rule "sdk_install_pkg" depends on rule "sdk", so skip rule "sdk"
make sdk_install_pkg ${FLAGS} -j$(nproc) -Orecurse -s

sudo apt-get install build-essential python-is-python3 -y

# install sgxsdk
sudo ./linux/installer/bin/sgx_linux_x64_sdk_*.bin <<EOF
no
/opt/intel/
EOF
source /opt/intel/sgxsdk/environment

# build sgxpsw, which relies on installed sgxsdk
# target "deb_local_repo" depends on target "deb_psw_pkg" which indirectly depends on target "psw"
# there is an error when make -j. (https://github.com/intel/linux-sgx/issues/755)
make deb_local_repo ${FLAGS} -j$(nproc) -Orecurse -s || make deb_local_repo ${FLAGS} -s

# install sgxpsw
sudo apt-get update
sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev -y
sudo apt-get install libsgx-launch.* libsgx-urts.* libsgx-epid.* libsgx-quote-ex.* libsgx-enclave-common.* libsgx-uae-service.* libsgx-ae-qe3.* libsgx-ae-qve.* libsgx-dcap-ql.* libsgx-dcap-default-qpl.* libsgx-dcap-quote-verify.* libsgx-ra-network.* libsgx-ra-uefi.* libsgx-qe3-logic.* -y
