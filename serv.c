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
        html_escape_string_UTF8(uid_escape_buf, 1024, results[i].user_id);
        printed += snprintf(buf+printed, buf_len-printed,
"<p>FP=%08X UID=\"%s\"</p>\r\n", results[i].id32, uid_escape_buf);
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
        resp = pretty_print_index_html(results, num_results, search, exact, after);
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
                   void *blooms_) {
    char *resp;
    int size, hcnt;
    struct inv_bloom_t **blooms = blooms_;
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
    for (i=0; blooms[i]; i++) {
        if(ibf_match(blooms[i], hcnt, size)) {
            resp = ibf_write(blooms[i]);
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

struct serv_state_t *
start_server(short port, char *root, struct keydb_t *db, struct inv_bloom_t **ibfs) {
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
    /* Add the difference estimator endpoint. */
    /* Add the bloom filter endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, "/ibf/:hcnt/:size", 0,
            &callback_bloom, ibfs);
    /* Add the system status endpoint. */

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
