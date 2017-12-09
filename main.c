#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include "hash.h"
#include "ibf.h"
#include "types.h"
#include "setdiff.h"
#include "key.h"
#include "keydb.h"
#include "serv.h"

#define MAX_PEERS 256

char done = 0;
char do_poll = 1;

struct peer_t {
    char host[1024];
    int interval;
    int countdown;
    int status;
};

void
handle_sig(int sig) {
    if (sig == SIGTERM) {
        done = 1;
    } else if (sig == SIGALRM) {
        do_poll = 1;
    }
} 

int main(int argc, char **argv) {
    char *hosts_file = "hosts.txt";
    FILE *hosts_in = NULL;
    char *db_name = "test.db";
    char *serv_root = "static";

    struct peer_t peers[MAX_PEERS];
    char verbose, create, ingest;
    struct keydb_t *db;
    struct serv_state_t *serv;
    int opt;
    int i;
    int port = 8080;
    unsigned alarm_int = 15;
    float excl_pct = 0;;

    verbose = create = ingest = 0;

    while ((opt = getopt(argc, argv, "a:cd:e:h:ip:r:v")) != -1) {
        switch (opt) {
            default:
            case '?': return -1;                break;
            case 'a': alarm_int = atoi(optarg); break;
            case 'c': create = 1;               break;
            case 'd': db_name = optarg;         break;
            case 'e': excl_pct = atof(optarg);  break;
            case 'h': hosts_file = optarg;      break;
            case 'i': ingest = 1;               break;
            case 'p': port = atoi(optarg);      break;
            case 'r': serv_root = optarg;       break;
            case 'v': verbose = 1;              break;
        }
    }

    hosts_in = fopen(hosts_file, "r");
    if (!hosts_in) {
        printf("Unable to open hosts file %s.\n", hosts_file);
        return -1;
    }

    for (i=0; i<MAX_PEERS; i++) {
        if (2 != fscanf(hosts_in, "%d %1024[^ \r\n\t\v\f]", &peers[i].interval, peers[i].host)) {
            peers[i].interval = 0;
            break;
        } else if (peers[i].interval == 0) {
            /* Skip invalid interval. */
            i--;
        }
    }
    printf("Read %d hosts from file:\n", i);
    for (i=0; i<MAX_PEERS; i++) {
        if (peers[i].interval == 0)
            break;
        printf("%d %s\n", peers[i].interval, peers[i].host);
    }


    db = open_key_db(db_name, create);
    if (!db) {
        if (create)
            printf("Unable to open/create database %s\n", db_name);
        else
            printf("Unable to open database %s\n", db_name);
        return -1;
    }

    if (ingest) {
        for (i=optind; i<argc; i++)
            if (ingest_file(db, argv[i], excl_pct)) return -1;
    } else {
        signal(SIGTERM, &handle_sig);
        signal(SIGALRM, &handle_sig);
        alarm(alarm_int);
        printf("Starting in server mode on port %d.\n", port);
        assert(serv=start_server(port, serv_root, db));
        while (pause()) {
            if (done) break;
            if (do_poll) {
                do_poll = 0;
                for (i=0; i<MAX_PEERS; i++) {
                    if (!peers[i].interval)
                        break;
                    peers[i].countdown -= alarm_int;
                    if (peers[i].countdown <= 0) {
                        printf("Polling %s.\n", peers[i].host);
                        peers[i].countdown = peers[i].interval;
                        peers[i].status = peer_with(db, peers[i].host);
                    }
                }
            }
        }
        printf("Received SIGTERM, terminating.\n");
        stop_server(serv);
    }

    if (close_key_db(db)) {
        printf("Error closing database.\n");
        return -1;
    }

    return 0;
}

