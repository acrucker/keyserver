#ifndef TYPES_H_
#define TYPES_H_

#include <stdint.h>
#include <stdlib.h>

#define BLOOM_HASH 4
#define IBF_MIN_SIZE 10

#define STRATA_IBF_SIZE 40
#define STRATA_IBF_MIN_DEPTH 1

#define STRATA_MAX_COUNT 5
#define BLOOM_MAX_COUNT 10

#define MAX_PEERS 256

struct inv_bloom_t;
struct keydb_t;
typedef uint8_t fp160[20];

struct pgp_key_t {
    char analyzed;
    size_t len;
    int version;
    uint8_t *data;
    uint64_t id64;
    uint32_t id32;
    char *user_id;
    fp160 fp;
    fp160 hash;
};

struct peer_t {
    char host[1024];
    int interval;
    int countdown;
    int status;
};

struct status_t {
    int port;
    int alarm_int;
    int nkeys;
    struct peer_t *peers;
};


#endif
