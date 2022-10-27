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
if [ ! -f Tool/sgx_edger8r ]
then
    cd edger8r
    dune build
    cd ..
    cp edger8r/_build/default/linux/Edger8r.bc Tool/sgx_edger8r
fi
# build
cmake ${CMAKE_FLAGS} -B ${BUILD_MOD}-build -DCMAKE_INSTALL_PREFIX=$(pwd)/install
cmake --build ${BUILD_MOD}-build -j$(nproc)
cmake --install ${BUILD_MOD}-build
