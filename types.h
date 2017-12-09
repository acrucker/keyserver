#ifndef TYPES_H_
#define TYPES_H_

#include <stdint.h>
#include <stdlib.h>

#define BLOOM_HASH 4
#define STRATA_IBF_SIZE 40
#define STRATA_IBF_DEPTH 16

#define BLOOM_MAX_COUNT 12

struct inv_bloom_t;
struct keydb_t;
typedef uint8_t fp160[20];

struct pgp_key_t {
    size_t len;
    int version;
    uint8_t *data;
    uint64_t id64;
    uint32_t id32;
    char *user_id;
    fp160 fp;
    fp160 hash;
};

#endif
