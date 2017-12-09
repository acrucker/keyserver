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
    struct pgp_key_t *down_key;
    struct keydb_t *db;
    struct serv_state_t *serv;
    uint64_t total;
    int read;
    int opt;
    int i;
    int port;
    int acc;
    float excl_pct;
    fp160 hash;

    struct pgp_key_t res_keys[16];
    int results;
    int est_diff;
    int ibf_min_size;

    struct inv_bloom_t *filters[16];
    struct inv_bloom_t *filter_down;
    struct strata_estimator_t *strata_down;
    struct strata_estimator_t *strata[16];

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
    for (i=0; i<BLOOM_MAX_COUNT; i++) {
        assert(filters[i]=ibf_allocate(BLOOM_HASH, acc));
        assert(!db_fill_ibf(db, filters[i]));
        acc *= 2;
    }
    filters[i] = 0;
    assert(strata[0]=strata_allocate(BLOOM_HASH, STRATA_IBF_SIZE, STRATA_IBF_DEPTH));
    strata[1] = NULL;
    printf("Filling strata from database:\n");
    assert(!db_fill_strata(db, strata[0]));

    if (peer_srv) {
        if ((strata_down = download_strata(peer_srv, BLOOM_HASH, STRATA_IBF_SIZE, STRATA_IBF_DEPTH))) {
            printf("Downloaded strata estimator:\n");
            est_diff = strata_estimate_diff(strata[0], strata_down);
            ibf_min_size = est_diff * 3;
            acc = 10;
            for (i=0; i<BLOOM_MAX_COUNT; i++) {
                if (acc >= ibf_min_size)
                    break;
                acc *= 2;
            }
            printf("Estimated difference is %d keys, looking for ibf >= %d = %d.\n", est_diff, ibf_min_size, acc);
            if ((filter_down = download_inv_bloom(peer_srv, BLOOM_HASH, acc))) {
                printf("Downloaded filter.\n");
                if (!ibf_subtract(filter_down, filters[i])) {
                    while (ibf_decode(filter_down, hash)) {
                        down_key = download_key(peer_srv, hash);
                        if (!down_key)
                            continue;
                        parse_key_metadata(down_key);
                        insert_key(db, down_key);
                    }
                }
                ibf_free(filter_down);
            } else { 
                printf("Failed to download filter.\n");
            }
            strata_free(strata_down);
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
                if (100*drand48() < excl_pct)
                    continue;
                if(insert_key(db, &key))
                    return -1;
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

