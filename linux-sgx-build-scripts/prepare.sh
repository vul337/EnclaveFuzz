#!/bin/bash
set -e

current_distr="ubuntu20.04"
script_dir=$(realpath $(dirname $0))
linux_sgx_src_dir="$(realpath ${script_dir}/../linux-sgx)"

sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl -y
sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0 -y

cd ${linux_sgx_src_dir}
make preparation
sudo cp external/toolset/${current_distr}/* /usr/local/bin

cd ${script_dir}
./set_apt_source.sh
