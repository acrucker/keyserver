#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "hash.h"
#include "ibf.h"
#include "types.h"
#include "setdiff.h"
#include "key.h"
#include "keydb.h"
#include "serv.h"

int main(int argc, char **argv) {
    FILE *in;
    char *db_name;
    char *serv_root;
    char *peer_srv;
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
    int acc;
    float excl_pct;

    struct pgp_key_t res_keys[16];
    int results;

    struct inv_bloom_t *filters[16];
    struct inv_bloom_t *filter_down;
    struct strata_estimator_t *strata[2];

    assert(strata[0]=strata_allocate(2, 10, 64));
    strata[1] = NULL;

    read = total = 0;
    verbose = create = ingest = 0;
    port = 8080;
    db_name = "test.db";
    query = NULL;
    serv_root = "static";
    peer_srv = NULL;
    excl_pct = 0.0;

    while ((opt = getopt(argc, argv, "cp:d:ivr:s:e:g:")) != -1) {
        switch (opt) {
            default:
            case '?': return -1;               break;
            case 'd': db_name = optarg;        break;
            case 'p': port = atoi(optarg);     break;
            case 'c': create = 1;              break;
            case 'i': ingest = 1;              break;
            case 'v': verbose = 1;             break;
            case 'r': serv_root = optarg;      break;
            case 's': query = optarg;          break;
            case 'e': excl_pct = atof(optarg); break;
            case 'g': peer_srv = optarg;       break;
        }
    }

    db = open_key_db(db_name, create);
    if (!db)
        return -1;
    acc = 10;
    for (i=0; i<7; i++) {
        assert(filters[i]=ibf_allocate(3, acc));
        assert(!db_fill_ibf(db, filters[i]));
        acc *= 2;
    }
    filters[i] = 0;
    printf("Filling strata from database.\n");
    assert(!db_fill_strata(db, strata[0]));
    /*strata_counts(strata);*/

    if (peer_srv) {
        if ((filter_down = download_inv_bloom(peer_srv, 3, 20))) {
            printf("Downloaded filter.\n");
        } else { 
            printf("Failed to download filter.\n");
        }
    } else if (query) {
        results = query_key_db(db, query, 16, res_keys, 0, 0);
        printf("Query \"%s\" matched %d keys\n", query, results);
        for (i=0; i<results; i++)
            pretty_print_key(&res_keys[i], "  ");
        if (results == 1) {
            tmp = ascii_armor_keys(&res_keys[0], 1);
            printf("\n%s\n", tmp);
            if (ascii_parse_key(tmp, &key)) {
                printf("Failed to parse generated key.\n");
            } else {
                printf("Parsed generated key:\n");
                parse_key_metadata(&key);
                pretty_print_key(&key, "");
                printf("%s\n", ascii_armor_keys(&key, 1));
            }
        }
    } else if (ingest) {
        printf("Randomly excluding %8.4f%% of keys.\n", excl_pct);
        srand48(time(NULL));
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
                if (100*drand48() < excl_pct)
                    continue;
                total += key.len;
                free(key.data);
                free(key.user_id);
                read++;
            }
            if (read %10000 == 0)
                printf("Ingesting...%d\n", read);

            fclose(in);
        }
        printf("Read %d keys (total %6.2f MiB).\n", read, total/1024.0/1024.0);
    } else {
        printf("Starting in server mode on port %d.\n", port);
        assert(serv=start_server(port, serv_root, db, filters, strata));
        getc(stdin);
        stop_server(serv);
    }

    if (close_key_db(db))
        return -1;

    for (i=0;;i++) {
        if (!filters[i])
            break;
        ibf_free(filters[i]);
    }
    strata_free(strata[0]);

    return 0;
}

