#!/bin/bash
# you may need `export EName="xxx"` in shell or soft-link "enclave.signed.so" to signed enclave file
set -e
mkdir -p output

if [[ $1 == 'debug' ]]; then
    PASS_BUILD_MOD=Debug
    PASS_CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"
    RT_MAKE_FLAGS="SGX_DEBUG=1 SGX_PRERELEASE=0"
else
    PASS_BUILD_MOD=Release
    PASS_CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
    RT_MAKE_FLAGS="SGX_DEBUG=0 SGX_PRERELEASE=1"
fi

# build pass
cd Pass
cmake ${PASS_CMAKE_FLAGS} -B ${PASS_BUILD_MOD}-build -DCMAKE_INSTALL_PREFIX=$(pwd)/../output
cmake --build ${PASS_BUILD_MOD}-build -j$(nproc)
rm -rf ../output/libSGXSanPass.so
cmake --install ${PASS_BUILD_MOD}-build

# build runtime
cd ../SGXSanRT
make -j$(nproc) -s ${RT_MAKE_FLAGS}
ln -fs ../SGXSanRT/libSGXSanRT{App.a,App.so,Enclave.a} ../output/
ln -fs ../SGXSanRT/SGXSanRTEnclave/SGXSanRTEnclave.edl ../output/
