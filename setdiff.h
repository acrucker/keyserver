#ifndef SETDIFF_H_
#define SETDIFF_H_

#include "types.h"

/* Allocates and returns a pointer to strata set-difference estimator with the
 * requested parameters. Returns NULL in the case of failure. */
struct strata_estimator_t *
strata_allocate(int    k /* Number of hashes per element */,
                size_t N /* Number of buckets */,
                int    c /* Number strata. */);

int
strata_match(struct strata_estimator_t *estimator, int k, size_t N, int c);

void
strata_free(struct strata_estimator_t *estimator);

void
strata_insert(struct strata_estimator_t *estimator, fp160 val);

void
strata_counts(struct strata_estimator_t *estimator);

/* Overwrites estimator_B completely. */
uint64_t
strata_estimate_diff(const struct strata_estimator_t *estimator_A,
                           struct strata_estimator_t *estimator_B);

char *
strata_write(const struct strata_estimator_t *estimator);

#endif
