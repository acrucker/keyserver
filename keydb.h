#ifndef _KEYDB_H
#define _KEYDB_H

#include "types.h"
#include "ibf.h"

struct keydb_t *
open_key_db(const char *filename);

int
insert_key(struct keydb_t *db, struct pgp_key_t *key);

int
retrieve_key(struct keydb_t *db, struct pgp_key_t *key, fp160 keyid);

int
db_fill_ibf(struct keydb_t *db, struct inv_bloom_t *filter);

#endif
