#include "keydb.h"
#include "key.h"
#include "ibf.h"
#include "setdiff.h"
#include "types.h"
#include "serv.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include <db.h>
#include <assert.h>
#include <errno.h>
/*#include <valgrind/memcheck.h>*/

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
    struct inv_bloom_t *filters[BLOOM_MAX_COUNT];
    struct strata_estimator_t *strata[STRATA_MAX_COUNT];
    pthread_rwlock_t lock;
};

int
retry_rdlock(struct keydb_t *db) {
    while (pthread_rwlock_rdlock(&db->lock)) {
        if (errno != EAGAIN)
            return -1;
        sleep(1);
    }
    return 0;
} 

int
unlock(struct keydb_t *db) {
    pthread_rwlock_unlock(&db->lock);
    return 0;
}

struct inv_bloom_t *
get_bloom(struct keydb_t *db, int idx) {
    if (idx >= BLOOM_MAX_COUNT)
        return NULL;
    return db->filters[idx];
}

struct strata_estimator_t *
get_strata(struct keydb_t *db, int idx) {
    if (idx >= STRATA_MAX_COUNT)
        return NULL;
    return db->strata[idx];
}

int
retry_wrlock(struct keydb_t *db) {
    while (pthread_rwlock_wrlock(&db->lock)) {
        if (errno != EAGAIN)
            return -1;
        sleep(1);
    }
    return 0;
} 

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
    db->key_idx[i].uid = strdup(uid);
    memcpy(db->key_idx[i].hash, hash, sizeof(fp160));
    memcpy(db->key_idx[i].fp, fp, sizeof(fp160));

    for (i=0; i<BLOOM_MAX_COUNT && db->filters[i]; i++)
        ibf_insert(db->filters[i], hash);
    for (i=0; i<STRATA_MAX_COUNT && db->strata[i]; i++)
        strata_insert(db->strata[i], hash);

    return 0;
}

struct keydb_t *
open_key_db(const char *filename, char create, char index) {
    struct keydb_t *ret;
    DBC *curs;
    DBT key, data;
    struct pgp_key_t pgp_key;
    int flags, i;
    int indexed;

    ret = malloc(sizeof(struct keydb_t));
    if (!ret) goto error;

    memset(ret, 0, sizeof(struct keydb_t));
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    data.flags = DB_DBT_REALLOC;

    for (i=0; i<BLOOM_MAX_COUNT; i++)
        assert(ret->filters[i]=ibf_allocate(BLOOM_HASH, (10<<i)));
    for (i=0; i<STRATA_MAX_COUNT; i++)
        assert(ret->strata[i]=strata_allocate(BLOOM_HASH, STRATA_IBF_SIZE, STRATA_IBF_MIN_DEPTH<<i));

    if (create) flags = DB_CREATE;
    else        flags = 0;

    if (db_create(&ret->dbp, NULL, 0)) goto error;

    if (ret->dbp->open(ret->dbp, NULL, filename, NULL, DB_HASH, flags, 0666))
        goto error;

    if (pthread_rwlock_init(&ret->lock, 0)) goto error;

    if (index) {
        if (ret->dbp->cursor(ret->dbp, NULL, &curs, 0)) goto error;
    
        indexed = 0;
        while (!curs->c_get(curs, &key, &data, DB_NEXT)) {
            pgp_key.data = data.data;
            pgp_key.len = data.size;

            if (parse_key_metadata(&pgp_key))
                continue;

            if (add_key_to_index(ret, pgp_key.version, pgp_key.len,
                        pgp_key.user_id, pgp_key.hash, pgp_key.fp, pgp_key.id32, pgp_key.id64))
                goto error;

            free(pgp_key.user_id);
            if (++indexed%10000 == 0)
                printf("Indexing...%d\n", indexed);

        }
        curs->c_close(curs);

        printf("Index contains %d keys.\n", ret->idx_count);
        free(data.data);
    }

    return ret;

error:
    free(data.data);
    if (!ret)
        return NULL;
    close_key_db(ret);
    return NULL;
}

int
ingest_file(struct keydb_t *db, const char *filename, float excl_pct) {
    FILE *in;
    struct pgp_key_t key;
    int read, total;

    read = total = 0;

    printf("Randomly excluding %8.4f%% of keys.\n", excl_pct);
    srand48(time(NULL));

    in = fopen(filename, "rb");
    if (!in) {
        fprintf(stderr, "Could not open dump file %s\n", filename);
        return -1;
    }
    
    key.user_id = NULL;
    while (!parse_from_dump(in, &key)) {
        if (parse_key_metadata(&key) || 100*drand48() < excl_pct) {
            free(key.data);
            free(key.user_id);
            key.user_id = NULL;
            continue;
        }
        /*if(insert_key(db, &key, 0, db->gtxnid)) {*/
        if(insert_key(db, &key, 0)) {
            printf("Failed to insert key.\n");
            return -1; 
        }

        total += key.len;
        free(key.data);
        free(key.user_id);
        key.user_id = NULL;
        read++;
        if (read %10000 == 0)
            printf("Ingesting...%d\n", read);
    }

    fclose(in);
    printf("Read %d keys (total %6.2f MiB) from %s\n", read, total/1024.0/1024.0, filename);
    return 0;
}


uint64_t
us_timestamp() {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec*1000000+time.tv_nsec/1000;
}

int
peer_with(struct keydb_t *db, char *srv) {
    struct strata_estimator_t *strata = NULL;
    struct inv_bloom_t *filter = NULL;
    struct pgp_key_t *key = NULL;
    int i, j, est_diff, ibf_min_size, acc;
    int count, ret;
    uint64_t start_time, strata_time, ibf_time, done_time;
    fp160 hash;

    start_time = us_timestamp();

    /* For efficient synchronization, try small strata estimators first. */
    for (i=0; i<STRATA_MAX_COUNT; i++) {
        strata = download_strata(srv, BLOOM_HASH, STRATA_IBF_SIZE, STRATA_IBF_MIN_DEPTH<<i);
        if (!strata) break;

        printf("Downloaded strata estimator %d.\n", i);
        if (retry_rdlock(db)) goto error;
        est_diff = strata_estimate_diff(db->strata[i], strata);
        unlock(db);
        if (est_diff == -1) { 
            printf("Estimator too small for useful result.\n");
            continue;
        }

        ibf_min_size = est_diff * 3;
        acc = 10;
        for (j=0; j<BLOOM_MAX_COUNT; j++) {
            if (acc >= ibf_min_size)
                break;
            acc *= 2;
        }
        break;
    }
    if (est_diff == -1) goto error;
    strata_time = us_timestamp();

    printf("Estimated difference is %d keys, looking for ibf >= %d = %d.\n", est_diff, ibf_min_size, acc);
    filter = download_inv_bloom(srv, BLOOM_HASH, acc);
    if (!filter) goto error;

    printf("Downloaded filter.\n");
    count = 0;
    if (retry_rdlock(db)) goto error;
    if (!ibf_subtract(filter, db->filters[j])) {
        ibf_time = us_timestamp();
        unlock(db);
        printf("Estimated difference from ibf=%ld.\n", ibf_count(filter));
        while ((ret = ibf_decode(filter, hash))) {
            if (ret < 0)
                continue;
            key = download_key(srv, hash);
            if (!key)
                goto error;
            if (parse_key_metadata(key))
                continue;
            insert_key(db, key, 1);
            count++;
        }
        printf("Added %d keys.\n", count);
        if (ibf_count(filter)) {
            printf("Undecodeable keys.\n");
            goto error;
        }
    } else {
        unlock(db);
        goto error;
    }

    done_time = us_timestamp();
    printf("%ld us to download and decode Strata.\n", strata_time-start_time);
    printf("%ld us to download and subtract Bloom.\n", ibf_time - strata_time);
    printf("%ld us to download all keys.\n", done_time - ibf_time);
    printf("%ld us total.\n", done_time - start_time);

    ibf_free(filter);
    strata_free(strata);
    return 0;

error:
    printf("Error synchronizing.\n");
    ibf_free(filter);
    strata_free(strata);
    return -1;
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
    if (retry_rdlock(db)) return -1;

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
    pthread_rwlock_unlock(&db->lock);
    return res_idx;
}

int
close_key_db(struct keydb_t *db) {
    int ret, i;
    if (retry_wrlock(db)) return -1;
    ret = 0;
    if (db->key_idx) {
        for (i=0; i<db->idx_count; i++)
            if (db->key_idx[i].uid)
                free(db->key_idx[i].uid);
        free(db->key_idx);
    }
    for(i=0; i<BLOOM_MAX_COUNT && db->filters[i]; i++)
        ibf_free(db->filters[i]);
    for(i=0; i<STRATA_MAX_COUNT && db->strata[i]; i++)
        strata_free(db->strata[i]);
    if (db->dbp)
        if (db->dbp->close(db->dbp, 0))
            ret = -1;
    free(db);
    return ret;
}

int
insert_key(struct keydb_t *db, struct pgp_key_t *pgp_key, int index) {
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

    if (retry_wrlock(db)) return -1;

    ret = db->dbp->put(db->dbp, NULL, &key, &data, DB_NOOVERWRITE);

    if (ret == DB_KEYEXIST)
        goto success_lock;
    else if (ret)
        goto err_lock;

    if (index)
        if (add_key_to_index(db, pgp_key->version, pgp_key->len, 
                    pgp_key->user_id, pgp_key->hash, pgp_key->fp, 
                    pgp_key->id32, pgp_key->id64))
            goto err_lock;

success_lock:
    unlock(db);
    return 0;
err_lock:
    unlock(db);
    return -1;
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
    memset(pgp_key, 0, sizeof(*pgp_key));

    data.flags = DB_DBT_MALLOC;

    key.data = hash;
    key.size = 20;

    ret = db->dbp->get(db->dbp, NULL, &key, &data, 0);

    if (ret)
        goto error;

    if (!(pgp_key->data = malloc(data.size))) goto error;

    memcpy(pgp_key->data, data.data, data.size);
    pgp_key->len = data.size;

    if (parse_key_metadata(pgp_key))
        goto error;

    return 0;

error:
    free(data.data);
    return -1;
}

