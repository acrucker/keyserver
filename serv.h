#ifndef SERV_H_
#define SERV_H_

#include <ulfius.h>
#include "keydb.h"
#include "ibf.h"

struct serv_state_t;

struct inv_bloom_t *
download_inv_bloom(char *host, int k, int N);

struct serv_state_t *
start_server(short port, char *root, struct keydb_t *db, 
        struct inv_bloom_t **ibfs, struct strata_estimator_t **strata);

void
stop_server(struct serv_state_t *serv);

#endif
