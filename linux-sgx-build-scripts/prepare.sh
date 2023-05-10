#!/bin/bash
set -e

script_dir=$(realpath -s $(dirname $0))
linux_sgx_src_dir="$(realpath -s ${script_dir}/../linux-sgx)"

sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev -y
sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake -y

cd ${linux_sgx_src_dir}
./download_prebuilt.sh
