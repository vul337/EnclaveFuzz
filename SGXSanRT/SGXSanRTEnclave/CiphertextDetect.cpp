#include <unordered_map>
#include <map>
#include <string>
#include <mbusafecrt.h>
#include "SGXSanPrintf.hpp"
#include "CiphertextDetect.hpp"
#include "SGXSanStackTrace.hpp"

bool isCiphertext(uint64_t addr, uint64_t size)
{
    if (size <= 0x100)
        return true;
    std::map<unsigned char, int> map;
    for (uint64_t i = 0; i < size; i++)
    {
        unsigned char byte = *(unsigned char *)(addr + i);
        if (map.count(byte) /* == 1 */)
        {
            map[byte]++;
        }
        else
        {
            map[byte] = 1;
        }
    }
    double byteAvgCnt = (int)size / /* (double)map.size() */ 256.0;
    PRINTF("[Cipher Detect]ByteAvgCnt = %f \n", byteAvgCnt);
    bool is_cipher = true;
    PRINTF("======== Byte Count Begin ========\n");
    std::string byteStr = "", cntStr = "";
    int buf_size = 1024;
    char buf[buf_size];
    int i = 1;
    for (auto iter = map.begin(); iter != map.end(); ++iter, i++)
    {
        if (iter->second > byteAvgCnt * 2 and iter->first != 0)
        {
            is_cipher = false;
            sprintf_s(buf, buf_size, "|*0x%02X*\t", iter->first);
        }
        else
        {
            sprintf_s(buf, buf_size, "| 0x%02X\t", iter->first);
        }

        byteStr = byteStr + buf;
        sprintf_s(buf, buf_size, "| %4d\t", iter->second);
        cntStr = cntStr + buf;
        if (i % 10 == 0)
        {
            PRINTF("%s \n", byteStr.c_str());
            PRINTF("%s \n", cntStr.c_str());
            byteStr = "";
            cntStr = "";
        }
    }
    if (i % 10 != 1)
    {
        PRINTF("%s \n", byteStr.c_str());
        PRINTF("%s \n", cntStr.c_str());
    }
    PRINTF("========= Byte Count End =========\n");
    return is_cipher;
}