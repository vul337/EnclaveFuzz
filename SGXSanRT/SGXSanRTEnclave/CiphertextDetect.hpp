#pragma once

#include <stdint.h>

typedef enum text_encryption {
  Unknown,
  Plaintext,
  Ciphertext
} text_encryption_t;

text_encryption_t isCiphertext(uint64_t addr, uint64_t size);
void check_output_hybrid(uint64_t addr, uint64_t size);