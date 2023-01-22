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

  double getProbability(size_t offset = 0) {
    uint64_t tmp;
    getBytes(&tmp, sizeof(uint64_t), offset);
    double res = ((double)tmp) / ((double)std::numeric_limits<uint64_t>::max());
    return res;
  }

  template <class T> T getInterger(size_t offset = 0) {
    T res;
    getBytes(&res, sizeof(T), offset);
    return res;
  }

  template <class T> T getIntergerInRange(T min, T max, size_t offset = 0) {
    static_assert(std::is_integral<T>::value, "An integral type is required.");
    static_assert(sizeof(T) <= sizeof(uint64_t), "Unsupported integral type.");
    if (min > max)
      abort();

    // Use the biggest type possible to hold the range and the result.
    uint64_t range = static_cast<uint64_t>(max) - min;
    uint64_t result = 0;
    getBytes(&result, sizeof(uint64_t), offset);

    // Avoid division by 0, in case |range + 1| results in overflow.
    if (range != std::numeric_limits<decltype(range)>::max())
      result = result % (range + 1);

    return static_cast<T>(min + result);
  }

private:
  std::string mRandFilePath;
  size_t mRandPoolSize;
  uint8_t *mRandPoolStart;
};