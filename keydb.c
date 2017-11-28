#include "keydb.h"
#include "key.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <db.h>

struct keydb_t {
    DB *dbp;
};

struct keydb_t *
open_key_db(const char *filename, char create) {
    struct keydb_t *ret;
    int flags;

    ret = malloc(sizeof(struct keydb_t));
    if (!ret)
        goto error;

    if (db_create(&ret->dbp, NULL, 0))
        goto error;

    if (create)
        flags = DB_CREATE;
    else
        flags = 0;

    if (ret->dbp->open(ret->dbp, NULL, filename, NULL, DB_HASH, flags, 0666))
        goto error;

    return ret;

error:
    if (!ret)
        return NULL;

    free(ret);

    return NULL;
}

int
close_key_db(struct keydb_t *db) {
    int ret;
    ret = 0;
    if (db->dbp->close(db->dbp, 0))
        ret = -1;
    free(db);
    return ret;
}

int
insert_key(struct keydb_t *db, struct pgp_key_t *pgp_key) {
    DBT key, data;
    int ret;

    if (!db) return -1;
    if (!db->dbp) return -1;
    if (!pgp_key) return -1;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    key.data = pgp_key->hash;
    key.size = 20;
    data.data = pgp_key->data;
    data.size = pgp_key->len;
    
    ret = db->dbp->put(db->dbp, NULL, &key, &data, DB_NOOVERWRITE);

    if (ret == DB_KEYEXIST)
        return 0;
    else if (ret)
        return -1;

    return 0;
}

int
retrieve_key(struct keydb_t *db, struct pgp_key_t *pgp_key, fp160 keyid) {
    DBT key, data;
    int ret;

    if (!db) return -1;
    if (!db->dbp) return -1;
    if (!pgp_key) return -1;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    key.data = keyid;
    key.size = 20;

    ret = db->dbp->get(db->dbp, NULL, &key, &data, 0);

    if (ret)
        return -1;

    pgp_key->data = data.data;
    pgp_key->len = data.size;

    if (parse_key_metadata(pgp_key))
        return -1;

    return 0;
}

int
db_fill_ibf(struct keydb_t *db, struct inv_bloom_t *filter) {
    return -1;
}
