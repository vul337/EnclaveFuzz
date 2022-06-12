#!/bin/bash
set -e

# clean pass
cd Pass
rm -rf  Debug-build \
        Release-build \
        ../output/lib{SensitiveLeakSanPass,SGXSanPass,SymbolSaverForLTOPass}.so

# clean runtime
cd ../SGXSanRT
make clean -s
rm -f ../output/libSGXSanRT{App.a,App.so,Enclave.a} ../output/SGXSanRTEnclave.edl
