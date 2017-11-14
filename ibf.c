#include "ibf.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>

struct inv_bloom_t {
    /* Arrays of bucket counts, xors, and xors of hashes. */
    uint64_t *counts; 
    uint64_t *id_sums; 
    uint64_t *hash_sums; 

    /* Function used for hashing. */
    uint64_t (*hash)(uint64_t, uint64_t); 

    int      k; /* Number of buckets to hash each element into. */
    size_t   N; /* Total number of buckets. */
    int      l; /* Effective length of all strings (bits). */
};

/* Allocates and returns a pointer to an inverse bloom filter with the
 * requested parameters. Returns NULL in the case of failure. */
struct inv_bloom_t *
ibf_allocate(int    k /* Number of hashes per element */,
             size_t N /* Number of buckets */,
             int    l /* Effective key length (bits) */,
             uint64_t (*hash)(uint64_t, uint64_t) /* Hash function */) {
    struct inv_bloom_t *filter;

    filter = malloc(sizeof(struct inv_bloom_t));
    if (!filter) goto fail;

    /* NULL out pointers to allow easy error handling. */
    memset(filter, 0, sizeof(struct inv_bloom_t));

    filter->counts = calloc(N, sizeof(uint64_t)); 
    if (!filter->counts) goto fail;

    filter->id_sums = calloc(N, sizeof(uint64_t));
    if (!filter->id_sums) goto fail;

    filter->hash_sums = calloc(N, sizeof(uint64_t));
    if (!filter->hash_sums) goto fail;

    filter->hash = hash;
    filter->k = k;
    filter->N = N;
    filter->l = l;
    
    return filter;

fail:
    /* This will free even partially-allocated filters. */
    ibf_free(filter);
    return NULL;
}

/* Frees all memory allocated by the filter. */
void
ibf_free(struct inv_bloom_t *filter) {
    if (!filter)
        return;
    if (filter->counts)
        free(filter->counts);
    if (filter->id_sums)
        free(filter->id_sums);
    if (filter->hash_sums)
        free(filter->hash_sums);
    free(filter);
}

/* Inserts the given element into the bloom filter. Always succeeds if the 
 * filter is valid. */
void
ibf_insert(struct inv_bloom_t *filter /* Filter to insert into */,
           uint64_t element /* Element to insert. */) {
    uint64_t i;
    uint64_t key;
    uint64_t hash_val;
    assert(filter);

    for (i=0; i<filter->k; i++) {
        key = (*filter->hash)(i, element) % filter->N;
        hash_val = (*filter->hash)(i+filter->k, element);

        filter->counts[key]++;
        filter->id_sums[key] ^= element;
        filter->hash_sums[key] ^= hash_val;
    }
}

/* Counts the number of elements in the bloom filter. */
uint64_t
ibf_count(struct inv_bloom_t *filter) {
    uint64_t count=0;
    size_t i;
    assert(filter);

    for (i=0; i<filter->N; i++) {
        count += filter->counts[i];
    }

    /* The count of total added hashes should be divisible by k */
    assert(count%filter->k == 0);
    count /= filter->k;

    return count;
}





