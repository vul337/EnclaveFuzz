#!/bin/bash
set -e

if [[ $1 == 'debug' ]]; then
    BUILD_MOD=Debug
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"
else
    BUILD_MOD=Release
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
fi

# build sgx_edger8r
cd edger8r/linux
ocamlbuild -cflag -g -lflag -g -libs str,unix Edger8r.byte
cd ../..
cp -f edger8r/linux/_build/Edger8r.byte Tool
# build
cmake ${CMAKE_FLAGS} -B ${BUILD_MOD}-build -DCMAKE_INSTALL_PREFIX=$(pwd)/install
cmake --build ${BUILD_MOD}-build -j$(nproc)
cmake --install ${BUILD_MOD}-build
