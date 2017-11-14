#ifndef _IBF_H
#define _IBF_H

#include <stdint.h>
#include <stddef.h>

struct inv_bloom_t;

/* Allocates and returns a pointer to an inverse bloom filter with the
 * requested parameters. Returns NULL in the case of failure. */
struct inv_bloom_t *
ibf_allocate(int    k /* Number of hashes per element */,
             size_t N /* Number of buckets */,
             int    l /* Effective key length (bits) */,
             uint64_t (*hash)(uint64_t, uint64_t) /* Hash function */);

/* Frees all memory allocated by the filter. */
void
ibf_free(struct inv_bloom_t *filter);

/* Inserts the given element into the bloom filter. Always succeeds if the 
 * filter is valid. */
void
ibf_insert(struct inv_bloom_t *filter /* Filter to insert into */,
           uint64_t element /* Element to insert. */);

/* Counts the number of elements in the bloom filter. */
uint64_t
ibf_count(struct inv_bloom_t *filter);

#endif
