# you may need `export EName="xxx"` in shell or soft-link "enclave.signed.so" to signed enclave file
set -e

cd Pass/SGXSanPass && ./build.sh
cd ../SensitiveLeakSanPass && ./build.sh
cd ../SymbolSaverForLTOPass && ./build.sh
cd ../../SGXSanRT && make -j$(nproc) -s