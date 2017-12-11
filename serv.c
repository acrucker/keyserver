#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "serv.h"
#include "key.h"
#include "keydb.h"
#include "util.h"

#define PATH_LEN 256
#define BUF_SIZE (1024*1024)
#define MAX_RESULTS 1000

struct serv_state_t {
    struct _u_instance inst;
};

int reply_response_status(struct _u_response *response,
                          int status,
                          const char *desc) {
    char *expl;
    char buf[BUF_SIZE];
    switch(status) {
        default:  status = 500;
        case 500: expl   = "Internal server error"; break;
        case 501: expl   = "Not implemented";       break;
        case 400: expl   = "Bad request";           break;
        case 403: expl   = "Invalid path";          break;
        case 404: expl   = "File not found";        break;
        case 302: expl   = "Redirecting";           break;
        case 200: expl   = "Successful";            break;
        case 201: expl   = "Resource created";      break;
    }
    snprintf(buf, BUF_SIZE, "%s: %s", expl, desc?desc:"");
    printf("Replying with code %d (%s)\n", status, buf);
    ulfius_set_string_body_response(response, status, buf);
    return U_CALLBACK_COMPLETE;
}

int callback_index(const struct _u_request *request, 
                   struct _u_response *response,
                   void *user_data) {
    ulfius_add_header_to_response(response, "Location", "/index.html");
    return reply_response_status(response, 302, "/index.html");
}

ssize_t 
callback_static_stream(void *fd, uint64_t offset, char *out_buf, size_t max) {
    ssize_t bytes_read;
    bytes_read = read(*(int*)fd, out_buf, max);
    if (-1 == bytes_read) {
        return U_STREAM_ERROR;
    } else if (0 == bytes_read) {
        return U_STREAM_END;
    } else {
        return bytes_read;
    }
}
/*
char *
url_decode_string(char *string) {
    char *ret;
    ret = malloc(strlen(string)+1);
    if (!ret) return NULL;
    while */

int
html_escape_string_UTF8(char *out_buf, size_t out_size, char *in_buf) {
    char c;
    int printed;
    int this_len;
    uint32_t code_point;
    char app_buf[11];
    char *app;

    printed = 0;
    if (out_size == 0)
        return 0;

    /* Read the next input character */
    while ((c = *in_buf++)) {
        code_point = 0;
        /* Find the number of bytes necessary to write the next escaped
         * character. */
        if (c == '<')        { app = "&lt;"; 
        } else if (c == '>') { app = "&gt;"; 
        } else if (c == '&') { app = "&amp;"; 
        } else if (c == '"') { app = "&quot;";
        } else if (c == '\'') { app = "&#x27;";
        } else if (c == '/') { app = "&#x2F;";
        } else if ((c&0x80) == 0x00) { 
            /* ASCII fast-path. */
            if (out_size == 1)
                break;
            *out_buf++ = c;
            out_size--;
            printed++;
            continue;
        } else if ((c&0xE0) == 0xC0) {
            code_point = (c&0x1F);
            c = *in_buf++; if (!c || ((c&0xC0) != 0x80)) break; 
            code_point <<= 6; code_point |= c&0x3F;
        } else if ((c&0xF0) == 0xE0) { 
            code_point = (c&0x0F);
            c = *in_buf++; if (!c || ((c&0xC0) != 0x80)) break; 
            code_point <<= 6; code_point |= c&0x3F;
            c = *in_buf++; if (!c || ((c&0xC0) != 0x80)) break; 
            code_point <<= 6; code_point |= c&0x3F;
        } else if ((c&0xF8) == 0xF0) {
            code_point = (c&0x07);
            c = *in_buf++; if (!c || ((c&0xC0) != 0x80)) break; 
            code_point <<= 6; code_point |= c&0x3F;
            c = *in_buf++; if (!c || ((c&0xC0) != 0x80)) break; 
            code_point <<= 6; code_point |= c&0x3F;
            c = *in_buf++; if (!c || ((c&0xC0) != 0x80)) break; 
            code_point <<= 6; code_point |= c&0x3F;
        }

        assert(code_point <= 0x10FFFF);
        if (code_point) {
            sprintf(app_buf, "&#x%X;",code_point);
            app = app_buf;
        }

        if (out_size < strlen(app)+1)
            break;
    
        this_len = sprintf(out_buf, "%s", app);
        printed += this_len;
        out_buf += this_len;
    }
    *out_buf = 0;
    return printed;
}

char *
pretty_print_index_html(struct pgp_key_t *results, int num_results, const char *query, char exact, int after) {
    char *buf;
    char uid_escape_buf[1024];
    int buf_len, printed, i, j, epos;
    char hash_printed[41];

    printed = 0;
    buf_len = 4096*num_results+8192;

    buf = malloc(buf_len);
    if (!buf) goto error;

    printed += snprintf(buf+printed, buf_len-printed,
"<html><title>AKS Search Results</title>\r\n"
"<body><h1>Results %d to %d for query \"%s\"</h1>\r\n",
    after+1, num_results+after, query);
    if (printed > buf_len) goto error;

    for (i=0; i<num_results; i++) {
        j=epos=0;
        print_fp160(results[i].hash, hash_printed);
        html_escape_string_UTF8(uid_escape_buf, 1024, results[i].user_id);
        printed += snprintf(buf+printed, buf_len-printed,
"<p>FP=<a href=\"/pks/lookup?op=download&search=%s\">%08X</a> UID=\"%s\"</p>\r\n", hash_printed, results[i].id32, uid_escape_buf);
        if (printed > buf_len) goto error;
    }
    printed += snprintf(buf+printed, buf_len-printed, "</body>");
    if (printed > buf_len) goto error;
    return buf;
error:
    free(buf);
    return NULL;
}

int callback_hkp_lookup(const struct _u_request *request,
                        struct _u_response *response,
                        void *db_) {
    char mr, exact, fingerprint, get, download, index, vindex;
    const char *op, *search;
    char *options, *opt_tok;
    struct keydb_t *db = db_;
    int num_results, after;
    struct pgp_key_t results[MAX_RESULTS];
    char *resp;
    int i;
    fp160 hash;

    after = 0;
    mr = exact = fingerprint = get = download = index = vindex = 0;
    printf("Received HKP request.\n");

    /* These are required options. */
    if (!u_map_has_key(request->map_url, "op"))
        return reply_response_status(response, 400, "Specify operation");
    if (!u_map_has_key(request->map_url, "search"))
        return reply_response_status(response, 400, "Specify search query");

    op = u_map_get(request->map_url, "op");
    if      (!strcmp(op,"get"))      get    = 1;
    else if (!strcmp(op,"download")) download = 1;
    else if (!strcmp(op,"index"))    index  = 1;
    else if (!strcmp(op,"vindex"))   vindex = 1;
    else return reply_response_status(response, 400, "Invalid operation");

    search = u_map_get(request->map_url, "search");

    if (u_map_has_key(request->map_url, "fingerprint")
            && !strcmp(u_map_get(request->map_url, "fingerprint"), "on"))
        fingerprint = 1;
    if (u_map_has_key(request->map_url, "exact")
            && !strcmp(u_map_get(request->map_url, "exact"), "on"))
        exact = 1;

    if (u_map_has_key(request->map_url, "after"))
        after = atoi(u_map_get(request->map_url, "after"));

    options = NULL;
    if (u_map_has_key(request->map_url, "options"))
        options = strndup(u_map_get(request->map_url, "options"), BUF_SIZE);
    if (options) {
        opt_tok = strtok(options, ",");
        while (opt_tok) {
            if (!strcmp(opt_tok,"mr")) mr = 1;
            opt_tok = strtok(NULL, ",");
        }
        free(options);
    }

    printf("Parsed HKP request successfully:\n");
    printf("\top=%s\n\tquery=%s\n\tfingerprint=%d\n\tmr=%d\n\texact=%d\n",
            get ? "get" : 
            download ? "download" : 
            index ? "index" : 
            vindex ? "vindex" : "error",
            search, fingerprint, mr, exact);
    if (index || get)
        num_results = query_key_db(db, search, MAX_RESULTS, results, exact, after);

    if (index) {
        if (!mr)  {
            resp = pretty_print_index_html(results, num_results, search, exact, after);
        } else {
            return reply_response_status(response, 501, "mr not supporte");
        }
    } else if (vindex) {
        return reply_response_status(response, 501, "vindex not supported");
    } else if (download) {
        parse_fp160(search, hash);
        if (retrieve_key(db, &results[0], hash))
            return reply_response_status(response, 404, search);
        resp = ascii_armor_keys(&results[0], 1);
        num_results = 1;
    } else if (get) {
        if (num_results == 0)
            return reply_response_status(response, 404, search);
        resp = ascii_armor_keys(results, num_results);
    }

    for (i=0; i<num_results; i++) {
        free(results[i].data);
        free(results[i].user_id);
    }

    if (resp) {
        response->binary_body = resp;
        response->binary_body_length = strlen(resp);
        response->status = 200;
        return U_CALLBACK_COMPLETE;
    } else {
        return reply_response_status(response, 502, "malloc");
    }
}

int callback_bloom(const struct _u_request *request,
                   struct _u_response *response,
                   void *db_) {
    char *resp;
    int size, hcnt;
    struct keydb_t *db = db_;
    int i;

    printf("Received ibf request.\n");

    /* These are required options. */
    if (!u_map_has_key(request->map_url, "size"))
        return reply_response_status(response, 400, "specify size");
    else
        size = atoi(u_map_get(request->map_url, "size"));

    if (!u_map_has_key(request->map_url, "hcnt"))
        return reply_response_status(response, 400, "specify number of hashes");
    else
        hcnt = atoi(u_map_get(request->map_url, "hcnt"));

    printf("Parsed ibf request successfully:\n");
    printf("\tsize=%d\n", size);
    printf("\thcnt=%d\n", hcnt);

    resp = NULL;
    for (i=0; get_bloom(db, i); i++) {
        if(ibf_match(get_bloom(db, i), hcnt, size)) {
            if (retry_rdlock(db)) goto serv_error;
            resp = ibf_write(get_bloom(db, i));
            unlock(db);
            break;
        }
    }

    if (resp) {
        response->binary_body = resp;
        response->binary_body_length = strlen(resp);
        response->status = 200;
        return U_CALLBACK_COMPLETE;
    } else {
        return reply_response_status(response, 404, "size/hash count not found");
    }
serv_error:
    return reply_response_status(response, 500, "Could not acquire rdlock");
}

int callback_strata(const struct _u_request *request,
                    struct _u_response *response,
                    void *db_) {
    char *resp;
    int size, hcnt, depth;
    struct keydb_t *db = db_;
    int i;

    printf("Received strata request.\n");

    /* These are required options. */
    if (!u_map_has_key(request->map_url, "size"))
        return reply_response_status(response, 400, "specify size");
    else
        size = atoi(u_map_get(request->map_url, "size"));

    if (!u_map_has_key(request->map_url, "hcnt"))
        return reply_response_status(response, 400, "specify number of hashes");
    else
        hcnt = atoi(u_map_get(request->map_url, "hcnt"));

    if (!u_map_has_key(request->map_url, "depth"))
        return reply_response_status(response, 400, "specify number of levels");
    else
        depth = atoi(u_map_get(request->map_url, "depth"));

    printf("Parsed strata request successfully:\n");
    printf("\tsize=%d\n", size);
    printf("\thcnt=%d\n", hcnt);
    printf("\tdepth=%d\n", depth);

    resp = NULL;
    for (i=0; get_strata(db, i); i++) {
        if(strata_match(get_strata(db, i), hcnt, size, depth)) {
            if (retry_rdlock(db)) goto serv_error;
            resp = strata_write(get_strata(db, i));
            unlock(db);
            break;
        }
    }

    if (resp) {
        response->binary_body = resp;
        response->binary_body_length = strlen(resp);
        response->status = 200;
        return U_CALLBACK_COMPLETE;
    } else {
        return reply_response_status(response, 404, "size/hash/depth count not found");
    }
serv_error:
    return reply_response_status(response, 500, "Could not acquire rdlock");
}

void free_static_stream(void *fd) {
    while (close(*(int*)fd) && errno == EINTR);
}

int callback_static(const struct _u_request *request, 
                    struct _u_response *response,
                    void *root) {
    int *fd;
    struct stat file_stat;
    char buf[BUF_SIZE];

    printf("Request for static page %s\n", request->http_url);
    if (!(fd=malloc(sizeof(int))))
        return reply_response_status(response, 500, "malloc");

    if (strstr(request->http_url, ".."))
        return reply_response_status(response, 403, "Path can't contain ..");

    if (PATH_LEN < snprintf(buf, BUF_SIZE, "%s/%s", (char*)root, request->http_url)) 
        return reply_response_status(response, 403, "Path too long");

    if (stat(buf, &file_stat)) {
        if (errno == ENOENT)
            return reply_response_status(response, 404, buf);
        else
            return reply_response_status(response, 500, buf);
    }

    if (-1 == (*fd=open(buf, 0)))
        return reply_response_status(response, 500, buf);

    if (U_OK != ulfius_set_stream_response(response, 200, 
                &callback_static_stream, &free_static_stream, file_stat.st_size,
                BUF_SIZE, fd))
        return reply_response_status(response, 500, NULL);

    return U_CALLBACK_COMPLETE;
}

int callback_add_key(const struct _u_request *request,
                     struct _u_response *response,
                     void *db_) {
    struct keydb_t *db = db_;
    struct pgp_key_t key;
    struct pgp_key_t test_key;
    char creat_buf[1024];
    char hash_buf[41];
    const char *keytext;
    
    printf("Received request to add key.\n");
    
    if (!u_map_has_key(request->map_post_body, "keytext"))
        return reply_response_status(response, 400, "Malformed request");
    
    keytext = u_map_get(request->map_post_body, "keytext");

    printf("Raw received keytext: \n%s\n", keytext);
    
    if (ascii_parse_key(keytext, &key))
        return reply_response_status(response, 400, "Malformed key");
    
    if (parse_key_metadata(&key)) {
        free(key.data);
        return reply_response_status(response, 400, "Malformed key");
    }
    
    if (retrieve_key(db, &test_key, key.hash)) {
        inner_free_key(&test_key);
        inner_free_key(&key);
        return reply_response_status(response, 403, "Cannot overwrite key.");
    }
    inner_free_key(&test_key);

    if (insert_key(db, &key, 1)) {
        inner_free_key(&key);
        return reply_response_status(response, 500, "Failed to insert key");
    }

    print_fp160(key.hash, hash_buf);
    snprintf(creat_buf, 1024, "Location: /pks/lookup?op=download&hash=%s", hash_buf);

    ulfius_add_header_to_response(response, "Location:", creat_buf);
    return reply_response_status(response, 201, hash_buf);

}

int callback_status(const struct _u_request *request,
                    struct _u_response *response,
                    void *stat_) {
    struct status_t *stat = stat_;
    char status_buf[BUF_SIZE];
    int w = 0;
    int i = 0;

    w += snprintf(status_buf+w, BUF_SIZE-w,
"<html> <head> <title>AKS Status Page</title> </head> <body>"
        "<h1> Keyserver Status: </h1><ul>");
    w += snprintf(status_buf+w, BUF_SIZE-w,
            "<li>Running on port: %d</li>", stat->port);
    w += snprintf(status_buf+w, BUF_SIZE-w,
            "<li>Alarm interval: %d</li>", stat->alarm_int);
    w += snprintf(status_buf+w, BUF_SIZE-w,
            "<li>Key count: %d</li>", stat->nkeys);
    w += snprintf(status_buf+w, BUF_SIZE-w, "</ul>");
    w += snprintf(status_buf+w, BUF_SIZE-w, "<h1> Keyserver Peers: </h1><ul>"); 

    for (i=0; i<MAX_PEERS; i++) {
        if (!stat->peers[i].interval)
            break;
        w += snprintf(status_buf+w, BUF_SIZE-w,
                "<li>%s: Int=%d Status=%s</li>", stat->peers[i].host,
                                                 stat->peers[i].interval,
                                                 stat->peers[i].status?"DOWN":"UP");
    }

    w += snprintf(status_buf+w, BUF_SIZE-w, "</ul>");
    w += snprintf(status_buf+w, BUF_SIZE-w, "</body> </html>");
    
    printf("Received request for status page.\n");
    ulfius_set_string_body_response(response, 200, status_buf);
    return U_CALLBACK_COMPLETE;

}

char *
download_url(char *url) {
    struct _u_request  req;
    struct _u_response resp;
    char *ret;

    ret = NULL;

    if (ulfius_init_request(&req) != U_OK) return NULL;
    if (ulfius_init_response(&resp) != U_OK) goto error_req;

    /*printf("Requesting URL %s\n", url);*/

    req.http_protocol = strdup("1.0");
    req.http_verb = strdup("GET");
    req.http_url = strdup(url);
    if (U_OK != ulfius_send_http_request(&req, &resp)) goto error_resp;

    /*printf("Request completed with status %ld, size %ld\n", resp.status, resp.binary_body_length);*/

    if (resp.status < 200 || resp.status >= 300)
        goto error_resp;

    ret = malloc(resp.binary_body_length+1);
    if (!ret) goto error_resp;

    memcpy(ret, resp.binary_body, resp.binary_body_length);
    ret[resp.binary_body_length] = 0;

/*success:*/
    ulfius_clean_request(&req);
    ulfius_clean_response(&resp);
    return ret;

error_resp:
    ulfius_clean_response(&resp);
error_req:
    ulfius_clean_request(&req);
    return NULL;
}

struct pgp_key_t *
download_key(char *srv, fp160 hash) {
    struct pgp_key_t *ret = NULL;
    char *string = NULL;
    char hash_buf[41];
    char url_buf[1024];

    ret = malloc(sizeof(*ret));
    if (!ret) goto error;

    print_fp160(hash, hash_buf);
    /*printf("Attempting to get key %s from %s.\n", hash_buf, srv);*/
    snprintf(url_buf, 1024, "%s/pks/lookup?op=download&search=%s", 
            srv, hash_buf);

    string = download_url(url_buf);

    if (ascii_parse_key(string, ret))
        goto error;

    free(string);
    return ret;

error:
    free(string);
    free(ret);
    return NULL;
}

struct strata_estimator_t *
download_strata(char *host, int k, int N, int c) {
    char *string = NULL;
    struct strata_estimator_t *estimator = NULL;

    char full_url[1024];
    snprintf(full_url, 1024, "%s/strata/%d/%d/%d", host, c, k, N);

    printf("Attempting to download the strata estimator (c=%d, k=%d, N=%d) @ %s\n", c, k, N, host);

    string = download_url(full_url);
    if (!string) return NULL;
    printf("Strata is %ld bytes.\n", strlen(string));

    estimator = strata_from_string(string);
    if (!estimator) goto error_string;

    if (!strata_match(estimator, k, N, c)) goto error_est;

/*success:*/
    free(string);
    return estimator;

error_est:
    strata_free(estimator);
error_string:
    free(string);
    return NULL;
}

struct inv_bloom_t *
download_inv_bloom(char *host, int k, int N) {
    char *string = NULL;
    struct inv_bloom_t *filt = NULL;

    char full_url[1024];
    snprintf(full_url, 1024, "%s/ibf/%d/%d", host, k, N);

    printf("Attempting to download the ibf (k=%d, N=%d) @ %s\n", k, N, host);

    string = download_url(full_url);
    if (!string) return NULL;
    printf("IBF is %ld bytes.\n", strlen(string));

    filt = ibf_from_string(string);
    if (!filt) goto error_string;

    if (!ibf_match(filt, k, N)) goto error_filt;

/*success:*/
    free(string);
    return filt;

error_filt:
    ibf_free(filt);
error_string:
    free(string);
    return NULL;
}

struct serv_state_t *
start_server(short port, char *root, struct keydb_t *db, struct status_t *stat) {
    struct serv_state_t *serv;

    if (!(serv=malloc(sizeof(struct serv_state_t))))
        goto fail;

    if (U_OK != ulfius_init_instance(&serv->inst, port, NULL, NULL))
        goto fail;

    /* Add the index.html endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, "/", 0,
            &callback_index, NULL);
    /* Add a key search endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, "/pks/lookup", 0,
            &callback_hkp_lookup, db);
    /* Add an endpoint for static files with lowest priority.*/
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, "/*", 100,
            &callback_static, root);
    /* Add the key upload endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "POST", NULL, "/pks/add", 0,
            &callback_add_key, db);
    /* Add the difference estimator endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, 
            "/strata/:depth/:hcnt/:size", 0, &callback_strata, db);
    /* Add the bloom filter endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, 
            "/ibf/:hcnt/:size", 0, &callback_bloom, db);
    /* Add the system status endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, 
            "/status", 0, &callback_status, stat);

    /* Start the server. */
    if (U_OK != ulfius_start_framework(&serv->inst))
        goto fail;

    return serv;

fail:
    stop_server(serv);
    return NULL;
}

void
stop_server(struct serv_state_t *serv) {
    if (!serv)
        return;
    ulfius_stop_framework(&serv->inst);
    ulfius_clean_instance(&serv->inst);
    free(serv);
}
