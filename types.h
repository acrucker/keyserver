#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stdlib.h>

struct inv_bloom_t;
typedef uint8_t fp160[20];

struct pgp_key_t {
    uint8_t *data;
    size_t len;
    uint64_t fp;
    char *user_id;
    fp160 hash;
};

#endif
