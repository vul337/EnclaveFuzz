#!/bin/bash
set -e
if [ -f "/opt/intel/sgxsdk/uninstall.sh" ]
then
    sudo /opt/intel/sgxsdk/uninstall.sh
fi

sudo apt-get purge libsgx-.* sgx-.* -y
