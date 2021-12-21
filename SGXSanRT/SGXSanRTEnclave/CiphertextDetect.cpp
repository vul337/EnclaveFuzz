#include <unordered_map>
#include <map>
#include <string>
#include <mbusafecrt.h>
#include "SGXSanPrintf.hpp"
#include "CiphertextDetect.hpp"
#include "SGXSanStackTrace.hpp"

bool isCiphertext(uint64_t addr, uint64_t size)
{
    if (size <= 0x1000)
        return true;
    int map[256 /* 2^8 */] = {0};
    // std::map<unsigned char, int> map;
    for (uint64_t i = 0; i < size; i++)
    {
        unsigned char byte = *(unsigned char *)(addr + i);
        map[byte]++;
        // if (map.count(byte) /* == 1 */)
        // {
        //     map[byte]++;
        // }
        // else
        // {
        //     map[byte] = 1;
        // }
    }

    double byteAvgCnt = (int)(size - map[0] /* maybe 0-padding in ciphertest */) / /* (double)map.size() */ 255.0;
    PRINTF("[Cipher Detect]ByteAvgCnt = %f \n", byteAvgCnt);
    bool is_cipher = true;
    PRINTF("======== Byte Count Begin ========\n");
    std::string byteStr = "", cntStr = "";
    int buf_size = 1024;
    char buf[buf_size];
    for (int i = 0; i < 256; i++)
    {
        if ((map[i] > byteAvgCnt * 2 || map[i] < byteAvgCnt / 2) and i != 0)
        {
            is_cipher = false;
            sprintf_s(buf, buf_size, "|*0x%02X*", i);
        }
        else
        {
            sprintf_s(buf, buf_size, "| 0x%02X ", i);
        }

        byteStr = byteStr + buf;
        sprintf_s(buf, buf_size, "| %4d ", map[i]);
        cntStr = cntStr + buf;
        if (i % 16 == 15)
        {
            PRINTF("________________________________________________________________________________________________________________\n"
                   "%s \n"
                   "%s \n",
                   byteStr.c_str(), cntStr.c_str());
            byteStr = "";
            cntStr = "";
        }
    }
    if (byteStr != "")
    {
        PRINTF("________________________________________________________________________________________________________________\n"
               "%s \n"
               "%s \n",
               byteStr.c_str(), cntStr.c_str());
    }
    PRINTF("========= Byte Count End =========\n");
    return is_cipher;
}