#include <stdio.h>
#include <assert.h>
#include "hash.h"
#include "ibf.h"

int 
main(int argc, char **argv) {
    struct inv_bloom_t *filter;
    uint64_t element;
    int ret;
    int i;
    assert(filter=ibf_allocate(2, 1024, 64, FNV_1a_64_dual));

    for (i=0; i<400; i++)
        ibf_insert(filter, i);

    while((ret=ibf_decode(filter, &element))) {
        if (ret > 0)
            printf("Removed element %lu from filter.\n", element);
        else
            printf("Removed negative element %lu from filter.\n", element);
    }

    printf("Filter had %lu undecodeable elements.\n", ibf_count(filter));

    ibf_free(filter);

    
    return 0;
}
