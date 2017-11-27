#include <stdio.h>
#include <assert.h>
#include "hash.h"
#include "ibf.h"
#include "types.h"
#include "key.h"

int main(int argc, char **argv) {
    FILE *in;
    struct pgp_key_t key;
    uint64_t total;
    int read;
    int i;

    struct inv_bloom_t *filter;
    assert(filter=ibf_allocate(2, 1024));

    read = total = 0;

    for (i=1; i<argc; i++) {
        in = fopen(argv[1], "rb");
        if (!in) {
            fprintf(stderr, "Could not open dump file %s\n", argv[1]);
            exit(1);
        }
        
        while (!parse_from_dump(in, &key)) {
            /*pretty_print_key(&key, "");*/
            total += key.len;
            ibf_insert(filter, key.hash);
            free(key.data);
            read++;
        }

        fclose(in);
    }
    printf("Read %d keys (total %6.2f MiB).\n", read, total/1024.0/1024.0);

    printf("IBF contains %lu keys.\n", ibf_count(filter));

    ibf_free(filter);

    return 0;
}

