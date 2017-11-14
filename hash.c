#include "hash.h"
#include "endian.h"
/*
uint64_t FNV_1a_64_raw(uint8_t *buf, int n) {
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t hash = 14695981039346656037ULL;

    for (; n>0; n--) {
        hash ^= *buf++;
        hash *= fnv_prime;
    }

    return hash;
}*/

uint64_t 
FNV_1a_64_dual(uint64_t a, uint64_t b) {
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t hash = 14695981039346656037ULL;
    int i;

    for (i=0; i<8; i++) {
        hash ^= a & 0xFF;
        a >>= 8;
        hash *= fnv_prime;
    }

    for (i=0; i<8; i++) {
        hash ^= b & 0xFF;
        b >>= 8;
        hash *= fnv_prime;
    }

    return hash;
}
