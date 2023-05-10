#!/bin/bash
set -e

script_dir=$(realpath -s $(dirname $0))
linux_sgx_src_dir="$(realpath -s ${script_dir}/../linux-sgx)"

FLAGS="$@"

cd ${linux_sgx_src_dir}

make ${FLAGS} -j$(nproc) -Orecurse -s

# build sdk
make sdk_install_pkg ${FLAGS} -j$(nproc) -Orecurse -s

# build psw
make deb_pkg ${FLAGS} -j$(nproc) -Orecurse -s
