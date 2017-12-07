#ifndef IBF_H_
#define IBF_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "types.h"

/* Allocates and returns a pointer to an inverse bloom filter with the
 * requested parameters. Returns NULL in the case of failure. */
struct inv_bloom_t *
ibf_allocate(int    k /* Number of hashes per element */,
             size_t N /* Number of buckets */);

/* Allocates and returns a pointer to a bloom filter that is a copy of filter.
 * returns NULL in the case of failure. */
struct inv_bloom_t *
ibf_copy(struct inv_bloom_t *filter);

/* Frees all memory allocated by the filter. */
void
ibf_free(struct inv_bloom_t *filter);

/* Inserts the given element into the bloom filter. Always succeeds if the 
 * filter is valid. */
void
ibf_insert(struct inv_bloom_t *filter /* Filter to insert into */,
           fp160 element /* Element to insert. */);

/* Deletes the given element from the bloom filter. May result in negative
 * counts. */
void
ibf_delete(struct inv_bloom_t *filter,
           fp160 element);

/* Decodes one element from filter, if possible, returning the result into
 * the value pointed by element. Returns 1 if a positive element was removed;
 * returns -1 if a negative element was removed; returns 0 if nothing could be
 * removed. This may be due to too many values being inserted or the filter 
 * being empty. */
int
ibf_decode(struct inv_bloom_t *filter /* Filter to search */,
           fp160 element /* Updated with the decoded element */);

/* Subtracts B from A in place. Returns 0 on success, non-zero on error. */
int
ibf_subtract(struct inv_bloom_t *filter_A,
             struct inv_bloom_t *filter_B);

/* Counts the number of elements in the bloom filter. */
uint64_t
ibf_count(struct inv_bloom_t *filter);

/* Writes out filter to an ASCII file. Returns 0 on success. */
int
ibf_write(FILE *out, struct inv_bloom_t *filter);

#endif
