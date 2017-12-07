#ifndef KEYDB_H_
#define KEYDB_H_

#include "types.h"
#include "ibf.h"

struct keydb_t *
open_key_db(const char *filename, char create);

int
query_key_db(struct keydb_t *db, const char *query, int max_results,
        struct pgp_key_t *keys, char exact, int after);

int
close_key_db(struct keydb_t *db);

int
insert_key(struct keydb_t *db, struct pgp_key_t *key);

int
retrieve_key(struct keydb_t *db, struct pgp_key_t *key, fp160 keyid);

int
db_fill_ibf(struct keydb_t *db, struct inv_bloom_t *filter);

#endif
