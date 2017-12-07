#include "setdiff.h"
#include "ibf.h"
#include <string.h>

struct strata_estimator_t {
    int    c;
    int    k;
    size_t N;
    struct inv_bloom_t **blooms;
};

struct strata_estimator_t *
strata_allocate(int    k /* Number of hashes per element */,
                size_t N /* Number of buckets */,
                int    c /* Number strata. */) {
    int i;
    struct strata_estimator_t *estimator;

    estimator = malloc(sizeof(struct strata_estimator_t));
    if (!estimator) goto error;
    estimator->c = c;
    estimator->k = k;
    estimator->N = N;

    estimator->blooms = malloc(c*sizeof(struct inv_bloom_t *));
    if (!estimator->blooms) goto error;

    for (i=0; i<c; i++)
        estimator->blooms[i] = ibf_allocate(k, N);

error:
    strata_free(estimator);
    return NULL;
}

void
strata_free(struct strata_estimator_t *estimator) {
    int i;
    if (!estimator)
        return;
    if (estimator->blooms)
        for (i=0; i<estimator->c; i++)
            ibf_free(estimator->blooms[i]);
    free(estimator->blooms);
    free(estimator);
}

void
strata_insert(struct strata_estimator_t *estimator, fp160 val) {
    int tzcount;
    int i;

    tzcount = 0;
    for (i=19; i>=0; i--) {
             if (val[i]&0x01) { tzcount += 0; break; }
        else if (val[i]&0x02) { tzcount += 1; break; }
        else if (val[i]&0x04) { tzcount += 2; break; }
        else if (val[i]&0x08) { tzcount += 3; break; }
        else if (val[i]&0x10) { tzcount += 4; break; }
        else if (val[i]&0x20) { tzcount += 5; break; }
        else if (val[i]&0x40) { tzcount += 6; break; }
        else if (val[i]&0x80) { tzcount += 7; break; }
        else                  { tzcount += 8; }
    }

    if (tzcount >= estimator->c)
        tzcount = estimator->c-1;

    ibf_insert(estimator->blooms[tzcount], val);
}

uint64_t
strata_estimate_diff(const struct strata_estimator_t *estimator_A,
                           struct strata_estimator_t *estimator_B) {
    int i;
    int total_decoded, local_decoded;
    fp160 dummy;

    if (estimator_A->c != estimator_B->c) return -1;
    if (estimator_A->k != estimator_B->k) return -1;
    if (estimator_A->N != estimator_B->N) return -1;

    total_decoded = 0;

    for (i=estimator_A->c; i>=0; i++) {
        if(ibf_subtract(estimator_B->blooms[i], estimator_A->blooms[i]))
            return -1;
       
        local_decoded = 0; 
        while (ibf_decode(estimator_B->blooms[i], dummy))
            local_decoded++;

        /* Not empty. */
        if (ibf_count(estimator_B->blooms[i])) {
            total_decoded *= 1<<(i+1);
            break;
        } else {
            total_decoded += local_decoded;
        }
    }
    return total_decoded;
}

char *
strata_write(const struct strata_estimator_t *estimator) {
    char *buf;
    char *ibf_buf;
    int w, i;

    buf = ibf_buf = NULL;
    w = 0;

    ibf_buf = ibf_write(estimator->blooms[0]);
    if (!ibf_buf) goto error;

    buf = malloc(strlen(ibf_buf)*estimator->c+1000);
    if (!buf) goto error;

    w+=sprintf(buf+w, "2:%d:%d:%lu\n",estimator->c, estimator->k, estimator->N);
    for (i=0; i<estimator->c; i++) {
        w+=sprintf(buf+w, "%s\n", ibf_buf);
        free(ibf_buf);
        if (i+1 == estimator->c)
            break;
        ibf_buf = ibf_write(estimator->blooms[i+1]);
        if (!ibf_buf) goto error;
    }
    return buf;

error:
    if (buf) free(buf);
    if (ibf_buf) free(ibf_buf);
    return NULL;
}
