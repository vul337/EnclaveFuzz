# how to use: cd into sgxsan_xxx directory in SGXAPP, call shell cmd(need to specify SGXSanPath) as follow
# for file in *.json;do python3 ${SGXSanPath}/tool/plot_byte_distr.py $file; done
import json
import sys
import os
import matplotlib.pyplot as plt

with open(sys.argv[1]) as json_file:
    data = json.load(json_file)
    byte_arr = data["byte_arr"]
    func_name = data["func_name"]
    bucket_num = data["bucket_num"]
    is_cipher = data["is_cipher"]
    count_per_bucket = (int)(256/bucket_num)
    plt.hist(byte_arr, bins=bucket_num, range=(0, 256), histtype='barstacked')
    plt.title("Function: "+func_name+"\nCipher: "+str(is_cipher))
    plt.xlabel("Byte Value(Bucket Num: "+str(bucket_num)+")")
    plt.ylabel("Bucket Count")
    plt.savefig(os.path.splitext(sys.argv[1])[0])
