#!/bin/bash
set -e

script_dir=$(realpath $(dirname $0))
linux_sgx_src_dir="$(realpath ${script_dir}/../linux-sgx)"

cd ${linux_sgx_src_dir}
make clean -s
