#!/bin/bash
set -e

sources_list_dir="/etc/apt/sources.list.d"
script_dir=$(realpath $(dirname $0))
linux_sgx_src_dir="$(realpath ${script_dir}/../linux-sgx)"

sudo mkdir -p ${sources_list_dir}
intel_sgx_list=${sources_list_dir}/intel-sgx.list

if [ -f ${intel_sgx_list} ]
then
  echo "[Already Exist] ${intel_sgx_list}"
else
  sudo touch ${intel_sgx_list}
  sudo sh -c "echo \"deb [trusted=yes arch=amd64] file:${linux_sgx_src_dir}/linux/installer/deb/sgx_debian_local_repo focal main\" >> ${intel_sgx_list}"
  echo "[Successfully Add] ${intel_sgx_list}"
fi
echo "[Prepare Successfully]"