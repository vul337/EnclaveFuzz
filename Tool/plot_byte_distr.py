# how to use: cd into sgxsan_xxx directory in SGXAPP, call shell cmd(need to specify SGXSanPath) as follow
# for file in *.json;do python3 ${SGXSanPath}/tool/plot_byte_distr.py $file; done
# or
# for file in ${target_dir}/*.json;do python3 plot_byte_distr.py $file; done
import json
import sys
import os
import matplotlib.pyplot as plt
import math

with open(sys.argv[1]) as json_file:
    data = json.load(json_file)
    byte_arr = data["byte_arr"]
    func_name = data["func_name"]
    bucket_num = data["bucket_num"]
    is_cipher = data["is_cipher"]
    len_of_byte_arr = len(byte_arr)
    count_per_bucket = round(
        (len_of_byte_arr-(byte_arr.count(0) if len_of_byte_arr >= 0x100 else 0))/bucket_num)
    if count_per_bucket == 0:
        count_per_bucket = 1
    plt.hist(byte_arr, bins=bucket_num, range=(0, 256), histtype='barstacked')
    plt.ylim(0, count_per_bucket*10)
    plt.title("Function: "+func_name+"\nCipher: "+str(is_cipher))
    plt.xlabel("Byte Value(Bucket Num: "+str(bucket_num)+")")
    plt.ylabel("Bucket Count")
    plt.savefig(os.path.splitext(sys.argv[1])[0])
