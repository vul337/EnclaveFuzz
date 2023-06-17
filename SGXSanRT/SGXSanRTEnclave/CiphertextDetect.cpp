#include "CiphertextDetect.hpp"

std::unordered_map<uint64_t /* callsite addr */,
                   std::vector<text_encryption_t> /* output type history */>
    output_history;
pthread_rwlock_t rwlock_output_history = PTHREAD_RWLOCK_INITIALIZER;
