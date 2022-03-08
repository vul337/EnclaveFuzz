#!/bin/bash
set -e
FLAG=$@
mkdir -p output
cd SGXSDKPatches
cd enclave_common_patch
./apply_patch.sh ${FLAG}
cd ../sdk_patch
./apply_patch.sh ${FLAG}