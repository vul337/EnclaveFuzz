#!/bin/bash
set -e
cd SGXSDKPatches
cd enclave_common_patch
./apply_patch.sh
cd ../sdk_patch
./apply_patch.sh