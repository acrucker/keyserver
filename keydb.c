#include "keydb.h"
#include "key.h"
#include "ibf.h"
#include "setdiff.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include <db.h>
#include <assert.h>

struct key_idx_t {
    int version;
    uint32_t id32;
    size_t size;
    uint64_t id64;
    char *uid;
    fp160 fp;
    fp160 hash;
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
                                fp160 hash, fp160 fp, uint32_t id32, uint64_t id64) {
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
    memcpy(db->key_idx[i].hash, hash, sizeof(fp160));
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
    }

    printf("Index contains %d keys.\n", ret->idx_count);

    return ret;

error:
    if (!ret)
        return NULL;
    close_key_db(ret);
    return NULL;
}

/* Returns the number of keys found, up to max_results. */
int
query_key_db(struct keydb_t *db, const char *query, int max_results,
        struct pgp_key_t *keys, char exact, int after) {
    /* Find the type of the query:
     *      1=32-bit keyID,
     *      2=64-bit keyID,
     *      3=160-bit fingerprint,
     *      4=user ID string.
     * Autodetected using HKP format. */
    char type;
    int i;
    int res_idx;
    char tmp[3];

    uint64_t id64;
    uint32_t id32;
    fp160 fp;

    type = res_idx = 0;
    tmp[2] = 0;

    if (query[0] == '0' && query[1] == 'x') {
        if (strlen(query) == 10) {
            type = 1;
            id32 = strtol(query, NULL, 16);
        } else if (strlen(query) == 18) {
            type = 2;
            id64 = strtol(query, NULL, 16);
        } else if (strlen(query) == 42) {
            parse_fp160(query+2, fp);
            type = 3;
        }
    } else {
        type = 4;
    }

    if (!type) return 0;

    for (i=0; i<db->idx_count; i++) {
        switch(type) {
            default:
                return 0;
                break;
            case 1: if (db->key_idx[i].id32 != id32)
                        continue; /* Try the next key. */
                    break;        /* Add this key to the results. */
            case 2: if (db->key_idx[i].id64 != id64)
                        continue;
                    break;
            case 3: if (neq_fp160(db->key_idx[i].fp, fp))
                        continue;
                    break;
            case 4: if ((exact && !strstr(db->key_idx[i].uid, query))
                    || (!exact && !strcasestr(db->key_idx[i].uid, query)))
                        continue;
                    break;
        }
        /* Skip a user-specified number of keys for pagination. */
        if (after) {
            after--;
            continue;
        }
        /* Get the key into the next slot from BDB. */
        if (retrieve_key(db, &keys[res_idx], db->key_idx[i].hash))
            break;
        if (parse_key_metadata(&keys[res_idx]))
            break;
        /* Limit the total number of keys. */
        if (++res_idx >= max_results)
            break;
    }
    return res_idx;
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
retrieve_key(struct keydb_t *db, struct pgp_key_t *pgp_key, fp160 hash) {
    DBT key, data;
    int ret;

    if (!db) return -1;
    if (!db->dbp) return -1;
    if (!pgp_key) return -1;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    key.data = hash;
    key.size = 20;

    ret = db->dbp->get(db->dbp, NULL, &key, &data, 0);

    if (ret)
        return -1;

    if (!(pgp_key->data = malloc(data.size))) return -1;

    memcpy(pgp_key->data, data.data, data.size);
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

int
db_fill_strata(struct keydb_t *db, struct strata_estimator_t *estimator) {
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

        strata_insert(estimator, pgp_key.hash);
        free(pgp_key.user_id);
    };

    return 0;
}
