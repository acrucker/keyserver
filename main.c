#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include "hash.h"
#include "ibf.h"
#include "types.h"
#include "key.h"
#include "keydb.h"

int main(int argc, char **argv) {
    FILE *in;
    char *db_name;
    char verbose, create, ingest;
    struct pgp_key_t key;
    struct keydb_t *db;
    uint64_t total;
    int read;
    int opt;
    int i;

    struct inv_bloom_t *filter;
    struct inv_bloom_t *filter_db;
    assert(filter=ibf_allocate(2, 80));
    assert(filter_db=ibf_allocate(2, 80));

    read = total = 0;
    verbose = create = ingest = 0;
    db_name = NULL;

    while ((opt = getopt(argc, argv, "cp:d:iv")) != -1) {
        switch (opt) {
            default:
            case '?':
                return -1;
                break;
            case 'd':
                db_name = optarg;
                break;
            case 'c':
                create = 1;
                break;
            case 'i':
                ingest = 1;
                break;
            case 'v':
                verbose = 1;
                break;
        }
    }

    db = open_key_db(db_name, create);
    if (!db)
        return -1;

    if (ingest) {
        for (i=optind; i<argc; i++) {
            in = fopen(argv[i], "rb");
            if (!in) {
                fprintf(stderr, "Could not open dump file %s\n", argv[1]);
                exit(1);
            }
            
            while (!parse_from_dump(in, &key)) {
                if(insert_key(db, &key))
                    return -1;
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
        db_fill_ibf(db, filter_db);
        printf("IBF from DB contains %lu keys.\n", ibf_count(filter_db));
        ibf_subtract(filter_db, filter);
        printf("IBF difference contains %lu keys.\n", ibf_count(filter_db));
    }

    if (verbose)
        ibf_write(stdout, filter);

    if (close_key_db(db))
        return -1;
    ibf_free(filter);

    return 0;
}

