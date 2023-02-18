#!/bin/bash
# After re-generate rand_file, orignal seed which lack partial parameters
# and use data from rand_file may not trigger same bug any more
rm rand_file
head -c 1M /dev/random > rand_file