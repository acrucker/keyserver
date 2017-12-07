#include "ibf.h"
#include "util.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <openssl/sha.h>

struct inv_bloom_t {
    /* Arrays of bucket counts, xors, and xors of hashes. */
    int32_t  *counts; 
    fp160    *id_sums; 
    fp160    *hash_sums; 

    int      k; /* Number of buckets to hash each element into. */
    size_t   N; /* Total number of buckets. */
};

/* Allocates and returns a pointer to an inverse bloom filter with the
 * requested parameters. Returns NULL in the case of failure. */
struct inv_bloom_t *
ibf_allocate(int    k /* Number of hashes per element */,
             size_t N /* Number of buckets */) {
    struct inv_bloom_t *filter;

    filter = malloc(sizeof(struct inv_bloom_t));
    if (!filter) goto fail;

    /* NULL out pointers to allow easy error handling. */
    memset(filter, 0, sizeof(struct inv_bloom_t));

    filter->counts = calloc(N, sizeof(int32_t)); 
    if (!filter->counts) goto fail;

    filter->id_sums = calloc(N, sizeof(fp160));
    if (!filter->id_sums) goto fail;

    filter->hash_sums = calloc(N, sizeof(fp160));
    if (!filter->hash_sums) goto fail;

    filter->k = k;
    filter->N = N;
    
    return filter;

fail:
    /* This will free even partially-allocated filters. */
    ibf_free(filter);
    return NULL;
}

int
ibf_match(struct inv_bloom_t *filter, int k, size_t N) {
    return filter->k == k && filter->N == N;
}

struct inv_bloom_t *
ibf_copy(struct inv_bloom_t *filter) {
    struct inv_bloom_t *copy;

    if (!filter) return NULL;
    copy = ibf_allocate(filter->k, filter->N);
    if (!copy)
        return NULL;
    
    copy->k = filter->k;
    copy->N = filter->N;

    memcpy(copy->counts, filter->counts, copy->N*sizeof(int32_t));
    memcpy(copy->id_sums, filter->id_sums, copy->N*sizeof(fp160));
    memcpy(copy->hash_sums, filter->hash_sums, copy->N*sizeof(fp160));

    return copy;
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

uint64_t
ibf_sha1_64_keyed(fp160 data, uint64_t index) {
    uint8_t buf[28];
    fp160 result;
    uint64_t ret;
    int i;

    for (i=0; i<8; i++) {
        buf[20+i] = (index>>(56-8*i))&0xFF;
    }
    
    memcpy(buf, data, 20);
    SHA1(buf, 28, result);;

    ret = 0;
    for (i=0; i<8; i++) {
        ret <<= 8;
        ret |= result[8-i];
    }
    return ret;
}

/* Updates dst ^= src. */
void 
ibf_fp160_xor(fp160 dst, fp160 src) {
    int i;

    for (i=0; i<20; i++) {
        dst[i] ^= src[i];
    }
}

/* Helper function to handle insertions and deletions. */
void
ibf_insdel(struct inv_bloom_t *filter,
           fp160 element,
           int ins /* 1 for insert, -1 for delete. */) {
    uint64_t i;
    uint64_t key;
    fp160 hash_val;
    assert(filter);

    SHA1(element, 20, hash_val);
    for (i=0; i<filter->k; i++) {
        key = ibf_sha1_64_keyed(element, i) % filter->N;

        filter->counts[key] += (ins>0)?1:-1;
        ibf_fp160_xor(filter->id_sums[key], element);
        ibf_fp160_xor(filter->hash_sums[key], hash_val);
    }
}

/* Inserts the given element into the bloom filter. Always succeeds if the 
 * filter is valid. */
void
ibf_insert(struct inv_bloom_t *filter /* Filter to insert into */,
           fp160 element /* Element to insert. */) {
    ibf_insdel(filter, element, 1);
}

/* Deletes the given element from the bloom filter. May result in negative
 * counts. */
void
ibf_delete(struct inv_bloom_t *filter,
           fp160 element) {
    ibf_insdel(filter, element, -1);
}

/* Decodes one element from filter, if possible, returning the result into
 * the value pointed by element. Returns the number of elements removed. */
int
ibf_decode(struct inv_bloom_t *filter /* Filter to search */,
           fp160 element /* Updated with the decoded element */) {
    size_t i;
    fp160 hash_val;
    int ins_del;
    assert(filter);

    for(i=0; i<filter->N; i++) {
        /* Need to have abs(count) == 1 to be able to decode. */
        if (abs(filter->counts[i]) != 1)
            continue;

        /* Check that both the hash and value match to the defined precision. */
        SHA1(filter->id_sums[i], 20, hash_val);
        if (neq_fp160(filter->id_sums[i], hash_val))
            continue;

        memcpy(&element[0], &filter->id_sums[i], 20);

        /* Update the filter to remove the value. */
        ins_del = -filter->counts[i]; /* -1 for delete if count == 1
                                       *  1 for insert if count == -1 */
        ibf_insdel(filter, element, ins_del);

        /* Return the value, and whether an insert or delete was performed. */
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

    for (i=0; i<filter_A->N; i++) {
        filter_A->counts[i] -= filter_B->counts[i];
        ibf_fp160_xor(filter_A->id_sums[i], filter_B->id_sums[i]);
        ibf_fp160_xor(filter_A->hash_sums[i], filter_B->hash_sums[i]);
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

/* Writes out filter to an ASCII file. Returns 0 on success. */
char *
ibf_write(struct inv_bloom_t *filter) {
    char *buf;
    int i, j;
    int w;

    w = 0;
    buf = malloc(100*filter->N);
    if (!buf) return NULL;

    assert(filter);
    w += sprintf(buf+w, "1:%d:%lu\n", filter->k, filter->N);
    for (i=0; i<filter->N; i++) {
        w += sprintf(buf+w, "%d:", filter->counts[i]);
        for(j=0; j<20; j++)
            w += sprintf(buf+w, "%02X", (filter->id_sums[i])[j]);
        w += sprintf(buf+w, ":");
        for(j=0; j<20; j++)
            w += sprintf(buf+w, "%02X", (filter->hash_sums[i])[j]);
        w += sprintf(buf+w, "\n");
    }
    return buf;
}

