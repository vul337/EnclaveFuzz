# you need `export EName="xxx"` in shell
cd SGXSanPass && ./build.sh
cd ../SensitiveLeakSanPass && ./build.sh
cd ../SGXSanRT && make -j$(nproc) -s