#include "ibf.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define _BM(x) (((x)==64)?(uint64_t)-1:(1<<(x))-1)

struct inv_bloom_t {
    /* Arrays of bucket counts, xors, and xors of hashes. */
    int64_t  *counts; 
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

/* Helper function to handle insertions and deletions. */
void
ibf_insdel(struct inv_bloom_t *filter,
           uint64_t element,
           int ins /* 1 for insert, -1 for delete. */) {
    uint64_t i;
    uint64_t key;
    uint64_t hash_val;
    assert(filter);

    element &= _BM(filter->l);

    for (i=0; i<filter->k; i++) {
        key = (*filter->hash)(1+i, element) % filter->N;
        hash_val = (*filter->hash)(0, element) & _BM(filter->l);

        filter->counts[key] += (ins>0)?1:-1;
        filter->id_sums[key] ^= element;
        filter->hash_sums[key] ^= hash_val;
    }
}


/* Inserts the given element into the bloom filter. Always succeeds if the 
 * filter is valid. */
void
ibf_insert(struct inv_bloom_t *filter /* Filter to insert into */,
           uint64_t element /* Element to insert. */) {
    ibf_insdel(filter, element, 1);
}

/* Deletes the given element from the bloom filter. May result in negative
 * counts. */
void
ibf_delete(struct inv_bloom_t *filter,
           uint64_t element) {
    ibf_insdel(filter, element, -1);
}

/* Decodes one element from filter, if possible, returning the result into
 * the value pointed by element. Returns the number of elements removed. */
int
ibf_decode(struct inv_bloom_t *filter /* Filter to search */,
           uint64_t *element /* Updated with the decoded element */) {
    size_t i;
    uint64_t val;
    uint64_t hash_val;
    int ins_del;
    assert(filter);

    for(i=0; i<filter->N; i++) {
        /* Need to have abs(count) == 1 to be able to decode. */
        if (abs(filter->counts[i]) != 1)
            continue;

        /* Check that both the hash and value match to the defined precision. */
        val = filter->id_sums[i];
        hash_val = (*filter->hash)(0, val) & _BM(filter->l);
        if (hash_val != filter->hash_sums[i])
            continue;

        /* Update the filter to remove the value. */
        ins_del = -filter->counts[i]; /* -1 for delete if count == 1
                                       *  1 for insert if count == -1 */
        ibf_insdel(filter, val, ins_del);

        /* Return the value, and whether an insert or delete was performed. */
        *element = val;
        return -ins_del;
    }
    return 0;
}

int
ibf_subtract(struct inv_bloom_t *filter_A,
             struct inv_bloom_t *filter_B) {
    size_t i;

    if (!filter_A)                        return -1;
    if (!filter_B)                        return -1;
    if (filter_A->k != filter_B->k)       return -1;
    if (filter_A->N != filter_B->N)       return -1;
    if (filter_A->l != filter_B->l)       return -1;
    if (filter_A->hash != filter_B->hash) return -1;

    for (i=0; i<filter_A->N; i++) {
        filter_A->counts[i] -= filter_B->counts[i];
        filter_A->id_sums[i] ^= filter_B->id_sums[i];
        filter_A->hash_sums[i] ^= filter_B->hash_sums[i];
    }

    return 0;
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





