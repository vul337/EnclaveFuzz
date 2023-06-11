#!/bin/bash
set -e

sources_list_dir="/etc/apt/sources.list.d"
script_dir=$(realpath -s $(dirname $0))
linux_sgx_src_dir="$(realpath -s ${script_dir}/../linux-sgx)"

sudo rm -f /usr/local/bin/{ar,as,ld,ld.gold,objcopy,objdump,ranlib}
sudo rm -f ${sources_list_dir}/intel-sgx.list

cd ${linux_sgx_src_dir}
make distclean -s
#comment to avoid user forget to git add recent modification
git clean -fd
git restore .
