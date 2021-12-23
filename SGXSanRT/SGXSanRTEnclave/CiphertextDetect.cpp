#include <string>
#include <mbusafecrt.h>
#include <vector>
#include "SGXSanPrintf.hpp"
#include "CiphertextDetect.hpp"
#include "SGXSanStackTrace.hpp"
#include "StackTrace.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanRTTBridge.hpp"

static inline int getArraySum(int *array, int size)
{
    int sum = 0;
    for (int i = 0; i < size; i++)
    {
        sum += array[i];
    }
    return sum;
}

static inline int getBucketNum(int size)
{
    return size >= 0x800   ? 0x100
           : size >= 0x100 ? 0x40
           : size >= 0x10  ? 0x4
           : size >= 0x2   ? 0x2
                           : 0x1;
}

bool isCiphertext(uint64_t addr, uint64_t size)
{
    if (size < 2)
        return true;
    int bucket_num = getBucketNum((int)size);

    int map[256 /* 2^8 */] = {0};
    for (uint64_t i = 0; i < size; i++)
    {
        unsigned char byte = *(unsigned char *)(addr + i);
        map[byte]++;
    }

    double CountPerBacket = (int)size / (double)bucket_num;
    if (size >= 0x100)
        CountPerBacket = (int)(size - map[0] /* maybe 0-padding in ciphertest */) / (double)(bucket_num - 1);
    PRINTF("[Cipher Detect] CountPerBacket = %f \n", CountPerBacket);

    bool is_cipher = true;
    PRINTF("======== Byte Count Begin ========\n");
    std::string byteStr = "", cntStr = "";
    int buf_size = 1024, step = 0x100 / bucket_num;
    char buf[buf_size];

    for (int i = 0; i < 256; i += step)
    {
        int sum = getArraySum(map + i, step);
        if ((sum > CountPerBacket * 2 || sum < CountPerBacket / 2) and (size >= 0x100 ? i != 0 : true))
        {
            is_cipher = false;
            sprintf_s(buf, buf_size, "|*0x%02X(0x%02X)*", i, step);
        }
        else
        {
            sprintf_s(buf, buf_size, "| 0x%02X(0x%02X) ", i, step);
        }

        byteStr = byteStr + buf;
        sprintf_s(buf, buf_size, "| %10d ", sum);
        cntStr = cntStr + buf;
        if ((i / step + 1) % 8 == 0)
        {
            PRINTF("%s \ns \n", byteStr.c_str(), cntStr.c_str());
            byteStr = "";
            cntStr = "";
        }
    }
    if (byteStr != "")
    {
        PRINTF("%s \n%s \n", byteStr.c_str(), cntStr.c_str());
    }
    PRINTF("========= Byte Count End =========\n");
    std::vector<int> ret_addrs;
    get_ret_addrs_in_stack(ret_addrs, g_enclave_base, 0);
    sgxsan_ocall_depcit_distribute(ret_addrs[1] - 1, (unsigned char *)addr, size, bucket_num, is_cipher);
    return is_cipher;
}