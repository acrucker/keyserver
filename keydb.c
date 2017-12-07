#include "keydb.h"
#include "key.h"
#include "ibf.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include <db.h>

struct key_idx_t {
    int version;
    uint32_t id32;
    size_t size;
    uint64_t id64;
    char *uid;
    fp160 fp;
    fp160 keyid;
};

struct keydb_t {
    DB *dbp;
    struct key_idx_t *key_idx;
    int idx_alloc;
    int idx_count;
    pthread_rwlock_t lock;
};

int
add_key_to_index(struct keydb_t *db, int version, int size, char *uid,
                                fp160 keyid, fp160 fp, uint32_t id32, uint64_t id64) {
    struct key_idx_t *tmp;
    int i;
    
    if (db->idx_alloc <= db->idx_count) {
        db->idx_alloc += 1024*1024;
        tmp = realloc(db->key_idx, db->idx_alloc*sizeof(struct key_idx_t));
        if (!tmp) return -1;
        db->key_idx = tmp;
    }

    i = db->idx_count++;
    db->key_idx[i].version = version;
    db->key_idx[i].size = size;
    db->key_idx[i].id32 = id32;
    db->key_idx[i].id64 = id64;
    db->key_idx[i].uid = uid;
    memcpy(db->key_idx[i].keyid, keyid, sizeof(fp160));
    memcpy(db->key_idx[i].fp, fp, sizeof(fp160));
    return 0;
}

struct keydb_t *
open_key_db(const char *filename, char create) {
    struct keydb_t *ret;
    DBC *curs;
    DBT key, data;
    struct pgp_key_t pgp_key;
    int flags;

    ret = malloc(sizeof(struct keydb_t));
    if (!ret) goto error;

    memset(ret, 0, sizeof(struct keydb_t));
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    if (db_create(&ret->dbp, NULL, 0)) goto error;

    if (create) flags = DB_CREATE;
    else        flags = 0;

    if (ret->dbp->open(ret->dbp, NULL, filename, NULL, DB_HASH, flags, 0666))
        goto error;

    if (pthread_rwlock_init(&ret->lock, NULL)) goto error;

    if (ret->dbp->cursor(ret->dbp, NULL, &curs, 0)) goto error;

    while (!curs->c_get(curs, &key, &data, DB_NEXT)) {
        pgp_key.data = data.data;
        pgp_key.len = data.size;

        if (parse_key_metadata(&pgp_key))
            continue;

        if (add_key_to_index(ret, pgp_key.version, pgp_key.len, 
                    pgp_key.user_id, pgp_key.hash, pgp_key.fp, pgp_key.id32, pgp_key.id64))
            goto error;

        if (ret->idx_count < 10)
            pretty_print_key(&pgp_key, "");
    }

    printf("Index contains %d keys.\n", ret->idx_count);

    return ret;

error:
    if (!ret)
        return NULL;
    close_key_db(ret);
    return NULL;
}

int
close_key_db(struct keydb_t *db) {
    int ret, i;
    ret = 0;
    if (db->key_idx) {
        for (i=0; i<db->idx_count; i++)
            if (db->key_idx[i].uid)
                free(db->key_idx[i].uid);
        free(db->key_idx);
    }
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
    DBC *curs;
    DB *dbp;
    DBT key, data;
    struct pgp_key_t pgp_key;
    int ret;

    dbp = db->dbp;
    ret = dbp->cursor(dbp, NULL, &curs, 0);
    if (ret)
        return -1;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    while (!curs->c_get(curs, &key, &data, DB_NEXT)) {
        pgp_key.data = data.data;
        pgp_key.len = data.size;

        if (parse_key_metadata(&pgp_key))
            continue;

        ibf_insert(filter, pgp_key.hash);
        free(pgp_key.user_id);
    };

    return 0;
}
