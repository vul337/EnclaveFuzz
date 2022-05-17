#!/bin/bash
set -e
FLAGS="$@"
mkdir -p output
cd SGXSDKPatches/enclave_common_patch
./apply_patch.sh ${FLAGS}
cd ../sdk_patch
./apply_patch.sh ${FLAGS}