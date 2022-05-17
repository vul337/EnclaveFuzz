#!/bin/bash
set -e

if [[ $1 == 'debug' ]]; then
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug -B build -S ."
else
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug -B build -S ."
fi
echo "CMAKE_FLAGS=\"${CMAKE_FLAGS}\""

cmake ${CMAKE_FLAGS}
cd build
make -j$(nproc) -s
ln -fs ../Pass/SGXSanPass/build/libSGXSanPass.so ../../../output/libSGXSanPass.so
