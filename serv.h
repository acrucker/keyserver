#ifndef SERV_H_
#define SERV_H_

#include <ulfius.h>
#include "setdiff.h"
#include "keydb.h"
#include "ibf.h"

struct serv_state_t;

struct pgp_key_t *
download_key(char *srv, fp160 hash);

struct inv_bloom_t *
download_inv_bloom(char *host, int k, int N);

struct strata_estimator_t *
download_strata(char *host, int k, int N, int c);

struct serv_state_t *
start_server(short port, char *root, struct keydb_t *db, struct status_t *stat);

void
stop_server(struct serv_state_t *serv);

#endif
