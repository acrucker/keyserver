#include <stdio.h>
#include <assert.h>
#include "hash.h"
#include "ibf.h"

int 
main(int argc, char **argv) {
    struct inv_bloom_t *filter;
    assert(filter=ibf_allocate(3, 16, 64, FNV_1a_64_dual));

    ibf_insert(filter, 1);
    ibf_insert(filter, 2);
    ibf_insert(filter, 3);
    
    assert(ibf_count(filter) == 3);
    
    return 0;
}
