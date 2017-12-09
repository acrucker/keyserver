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

    return estimator;

error:
    strata_free(estimator);
    return NULL;
}

int
strata_match(struct strata_estimator_t *estimator, int k, size_t N, int c) {
    return estimator->k == k
        && estimator->N == N
        && estimator->c == c;
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
strata_counts(struct strata_estimator_t *estimator) {
    int i;
    for (i=0; i<estimator->c; i++)
        printf("%2d: %8lu %8lu\n", i, ibf_count(estimator->blooms[i]),
                                      ibf_count(estimator->blooms[i])*(1<<(i+1)));
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

    for (i=estimator_A->c-1; i>=0; i--) {
        /*printf("Trying to decode stratum %d.\n", i);
        if (ibf_count(estimator_B->blooms[i])) {
            printf("Local filter: %s\n", ibf_write(estimator_A->blooms[i]));
            printf("Remote filter: %s\n", ibf_write(estimator_B->blooms[i]));
        }*/
        if(ibf_subtract(estimator_B->blooms[i], estimator_A->blooms[i]))
            return -1;

        /*printf("Subtracted filter for stratum %d contains %ld elements.\n", 
                i, ibf_count(estimator_B->blooms[i]));
        if (ibf_count(estimator_B->blooms[i])) {
            printf("Trying to decode filter: %s\n", ibf_write(estimator_B->blooms[i]));
        }*/
       
        local_decoded = 0; 
        while (ibf_decode(estimator_B->blooms[i], dummy))
            local_decoded++;

        /*if (ibf_count(estimator_B->blooms[i])) {
            printf("Decoded %d entries.\n", local_decoded);
        }*/

        /* Not empty. */
        if (ibf_count(estimator_B->blooms[i])) {
            /*printf("Found undecodeable IBF remainder at level %d:%s\n", i, 
                    ibf_write(estimator_B->blooms[i]));
            printf("Previously decoded: %d\nScaling factor: %d\n",
                    total_decoded, 1<<(i+1));*/
            total_decoded *= 1<<(i+1);
            if (total_decoded == 0)
                total_decoded = -1;
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

    w+=sprintf(buf+w, "STRATA:%d:%d:%lu\n",estimator->c, estimator->k, estimator->N);
    for (i=0; i<estimator->c; i++) {
        w+=sprintf(buf+w, "%s", ibf_buf);
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

struct strata_estimator_t *
strata_from_string(char *string) {
    int c, k, N, i;
    char *ibf;
    struct strata_estimator_t *estimator = NULL;
    if (3 != sscanf(string, "STRATA:%d:%d:%d", &c, &k, &N))
        goto error;

    estimator = malloc(sizeof(*estimator));
    if (!estimator) goto error;

    estimator->blooms = calloc(c, sizeof(struct inv_bloom_t *));
    if (!estimator->blooms) goto error_est;

    estimator->c = c;
    estimator->k = k;
    estimator->N = N;

    ibf = string;

    for (i=0; i<c; i++) {
        /* Advance to the next ibf to parse. */
        ibf = strstr(ibf+1, "IBF:");
        estimator->blooms[i] = ibf_from_string(ibf);
        if (!estimator->blooms[i]) goto free_blooms;
        if (!ibf_match(estimator->blooms[i], k, N)) goto free_blooms;
    }

    return estimator;

free_blooms:
    for (i=0; i<c; i++)
        if (estimator->blooms[i])
            free(estimator->blooms[i]);
error_est:
    free(estimator);
error:
    return NULL;
}

