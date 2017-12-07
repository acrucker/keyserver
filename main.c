#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include "hash.h"
#include "ibf.h"
#include "types.h"
#include "key.h"
#include "keydb.h"
#include "serv.h"

int main(int argc, char **argv) {
    FILE *in;
    char *db_name;
    char *serv_root;
    char *query;
    char *tmp;
    char verbose, create, ingest;
    struct pgp_key_t key;
    struct keydb_t *db;
    struct serv_state_t *serv;
    uint64_t total;
    int read;
    int opt;
    int i;
    int port;

    struct pgp_key_t res_keys[16];
    int results;

    struct inv_bloom_t *filter;
    struct inv_bloom_t *filter_db;
    assert(filter=ibf_allocate(2, 80));
    assert(filter_db=ibf_allocate(2, 80));

    read = total = 0;
    verbose = create = ingest = 0;
    port = 8080;
    db_name = "test.db";
    query = NULL;
    serv_root = "static";

    while ((opt = getopt(argc, argv, "cp:d:ivr:s:")) != -1) {
        switch (opt) {
            default:
            case '?': return -1;           break;
            case 'd': db_name = optarg;    break;
            case 'p': port = atoi(optarg); break;
            case 'c': create = 1;          break;
            case 'i': ingest = 1;          break;
            case 'v': verbose = 1;         break;
            case 'r': serv_root = optarg;  break;
            case 's': query = optarg;      break;
        }
    }

    db = open_key_db(db_name, create);
    if (!db)
        return -1;

    if (query) {
        results = query_key_db(db, query, 16, res_keys, 0, 0);
        printf("Query \"%s\" matched %d keys\n", query, results);
        for (i=0; i<results; i++)
            pretty_print_key(&res_keys[i], "  ");
        if (results == 1) {
            tmp = ascii_armor_key(&res_keys[0]);
            printf("\n%s\n", tmp);
            if (ascii_parse_key(tmp, &key)) {
                printf("Failed to parse generated key.\n");
            } else {
                printf("Parsed generated key:\n");
                parse_key_metadata(&key);
                pretty_print_key(&key, "");
                printf("%s\n", ascii_armor_key(&key));
            }
        }
    } else if (ingest) {
        for (i=optind; i<argc; i++) {
            in = fopen(argv[i], "rb");
            if (!in) {
                fprintf(stderr, "Could not open dump file %s\n", argv[1]);
                exit(1);
            }
            
            while (!parse_from_dump(in, &key)) {
                if (parse_key_metadata(&key))
                    continue;
                if(insert_key(db, &key))
                    return -1;
                total += key.len;
                ibf_insert(filter, key.hash);
                free(key.data);
                free(key.user_id);
                read++;
            }

            fclose(in);
        }
        printf("Read %d keys (total %6.2f MiB).\n", read, total/1024.0/1024.0);
    } else {
        printf("Starting in server mode on port %d.\n", port);
        assert(serv=start_server(port, serv_root, db));
        getc(stdin);
        stop_server(serv);
    }

    if (verbose)
        ibf_write(stdout, filter);

    if (close_key_db(db))
        return -1;
    ibf_free(filter);
    ibf_free(filter_db);

    return 0;
}

