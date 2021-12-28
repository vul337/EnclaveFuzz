# you need `export Enclave_File_Name="xxx"` in shell
cd SGXSanPass && ./build.sh
cd ../SGXSanRT && make -j$(nproc) -s