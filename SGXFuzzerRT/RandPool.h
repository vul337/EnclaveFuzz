#pragma once
#include "SGXSanConfig.h"
#include "libFuzzerCallback.h"
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

class RandPool {
public:
  RandPool() {
    mRandFilePath = std::string(SGXSAN_DIR "/SGXFuzzerRT/rand_file");
    int fd = open(mRandFilePath.c_str(), O_RDONLY);
    sgxfuzz_assert(fd != -1);
    sgxfuzz_assert(lseek(fd, 0, mRandPoolSize) == 0);

    struct stat s;
    sgxfuzz_assert(fstat(fd, &s) == 0);
    mRandPoolSize = s.st_size;

    mRandPoolStart =
        (uint8_t *)mmap(NULL, mRandPoolSize, PROT_READ, MAP_PRIVATE, fd, 0);
    sgxfuzz_assert(MAP_FAILED != mRandPoolStart);
    close(fd);
  }

  ~RandPool() { sgxfuzz_assert(munmap(mRandPoolStart, mRandPoolSize) == 0); }

  size_t getPoolSize() { return mRandPoolSize; }

  void getBytes(void *buf, size_t size, size_t offset = 0) {
    // Pre check
    if (size == 0) {
      return;
    }
    sgxfuzz_assert(buf);
    offset = offset % mRandPoolSize;

    uint8_t *buf_u8 = (uint8_t *)buf;

    // Copy from random pool
    if (offset + size <= mRandPoolSize) {
      memcpy(buf, mRandPoolStart + offset, size);
    } else {
      size_t size2cp = mRandPoolSize - offset;
      memcpy(buf_u8, mRandPoolStart + offset, size2cp);
      buf_u8 += size2cp;
      size -= size2cp;
      while (size > 0) {
        size_t size2cp = std::min(size, mRandPoolSize);
        memcpy(buf_u8, mRandPoolStart, size2cp);
        size -= size2cp;
        buf_u8 += size2cp;
      }
    }
  }

private:
  std::string mRandFilePath;
  size_t mRandPoolSize;
  uint8_t *mRandPoolStart;
};