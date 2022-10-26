#!/bin/bash
set -e

if [[ $1 == 'debug' ]]; then
    BUILD_MOD=Debug
else
    BUILD_MOD=Release
fi

# build sgx_edger8r
if [ ! -f Tool/sgx_edger8r ]
then
    cd edger8r
    dune build
    cd ..
    cp edger8r/_build/default/linux/Edger8r.bc Tool/sgx_edger8r
fi
# build
cmake -DCMAKE_BUILD_TYPE=${BUILD_MOD} -B ${BUILD_MOD}-build -DCMAKE_INSTALL_PREFIX=$(pwd)/install -DHOST_ASAN=0
cmake --build ${BUILD_MOD}-build -j$(nproc)
cmake --install ${BUILD_MOD}-build
