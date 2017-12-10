#ifndef KEYDB_H_
#define KEYDB_H_

#include <db.h>
#include "types.h"
#include "ibf.h"
#include "setdiff.h"

struct keydb_t *
open_key_db(const char *filename, char create, char index);

int
query_key_db(struct keydb_t *db, const char *query, int max_results,
        struct pgp_key_t *keys, char exact, int after);

int
ingest_file(struct keydb_t *db, const char *filename, float excl_pct);

int
close_key_db(struct keydb_t *db);

int
peer_with(struct keydb_t *db, char *srv);

int 
retry_rdlock(struct keydb_t *db);

int 
retry_wrlock(struct keydb_t *db);

int 
unlock(struct keydb_t *db);

struct inv_bloom_t *
get_bloom(struct keydb_t *db, int idx);

struct strata_estimator_t *
get_strata(struct keydb_t *db, int idx);

int
insert_key(struct keydb_t *db, struct pgp_key_t *pgp_key, int index);

int
retrieve_key(struct keydb_t *db, struct pgp_key_t *key, fp160 keyid);

#endif
