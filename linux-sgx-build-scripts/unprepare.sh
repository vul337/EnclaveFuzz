#!/bin/bash
set -e

script_dir=$(realpath -s $(dirname $0))
linux_sgx_src_dir="$(realpath -s ${script_dir}/../linux-sgx)"

cd ${linux_sgx_src_dir}
make clean -s
#comment to avoid user forget to git add recent modification
git clean -fd
git restore .
