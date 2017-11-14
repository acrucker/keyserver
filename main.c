#include <stdio.h>
#include <assert.h>
#include "hash.h"
#include "ibf.h"

int 
main(int argc, char **argv) {
    struct inv_bloom_t *filter_A;
    struct inv_bloom_t *filter_B;
    uint64_t element;
    int ret;
    int i;
    assert(filter_A=ibf_allocate(2, 1024, 64, FNV_1a_64_dual));
    assert(filter_B=ibf_allocate(2, 1024, 64, FNV_1a_64_dual));

    for (i=5; i<400000; i++)
        ibf_insert(filter_A, i);
    for (i=0; i<399990; i++)
        ibf_insert(filter_B, i);

    assert(!ibf_subtract(filter_A, filter_B));

    while((ret=ibf_decode(filter_A, &element))) {
        if (ret > 0)
            printf("Removed element %lu from filter.\n", element);
        else
            printf("Removed negative element %lu from filter.\n", element);
    }

    printf("Filter had %lu undecodeable elements.\n", ibf_count(filter_A));

    ibf_free(filter_A);
    ibf_free(filter_B);

    
    return 0;
}
