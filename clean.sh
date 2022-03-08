set -e

cd Pass/SGXSanPass && ./clean.sh
cd ../SensitiveLeakSanPass && ./clean.sh
cd ../SymbolSaverForLTOPass && ./clean.sh
cd ../../SGXSanRT && make clean

cd ..
rm -f ../output/SGXSanRTEnclave.edl