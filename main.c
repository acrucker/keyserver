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
    char verbose, create, ingest;
    struct pgp_key_t key;
    struct keydb_t *db;
    struct serv_state_t *serv;
    uint64_t total;
    int read;
    int opt;
    int i;
    int port;
    float excl_pct;

    read = total = 0;
    verbose = create = ingest = 0;
    port = 8080;
    db_name = "test.db";
    serv_root = "static";
    peer_srv = NULL;
    excl_pct = 0.0;

    while ((opt = getopt(argc, argv, "cp:d:ivr:e:g:")) != -1) {
        switch (opt) {
            default:
            case '?': return -1;               break;
            case 'd': db_name = optarg;        break;
            case 'p': port = atoi(optarg);     break;
            case 'c': create = 1;              break;
            case 'i': ingest = 1;              break;
            case 'v': verbose = 1;             break;
            case 'r': serv_root = optarg;      break;
            case 'e': excl_pct = atof(optarg); break;
            case 'g': peer_srv = optarg;       break;
        }
    }

    db = open_key_db(db_name, create);
    if (!db) {
        if (create)
            printf("Unable to open/create database %s\n", db_name);
        else
            printf("Unable to open database %s\n", db_name);
        return -1;
    }

    if (peer_srv) {
        peer_with(db, peer_srv);
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
        assert(serv=start_server(port, serv_root, db));
        getc(stdin);
        stop_server(serv);
    }

    if (close_key_db(db))
        return -1;

    return 0;
}

