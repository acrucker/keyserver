#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "serv.h"

#define PATH_LEN 256
#define BUF_SIZE 16384

struct serv_state_t {
    struct _u_instance inst;
};

int reply_response_status(struct _u_response *response,
                          int status,
                          char *desc) {
    char *expl;
    char buf[BUF_SIZE];
    switch(status) {
        default:  status = 500;
        case 500: expl   = "Internal server error"; break;
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
start_server(short port, char *root) {
    struct serv_state_t *serv;

    if (!(serv=malloc(sizeof(struct serv_state_t))))
        goto fail;

    if (U_OK != ulfius_init_instance(&serv->inst, port, NULL, NULL))
        goto fail;

    /* Add the index.html endpoint. */
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, "/", 0,
            &callback_index, NULL);
    /* Add a key search endpoint. */
    /* Add an endpoint for static files with lowest priority.*/
    ulfius_add_endpoint_by_val(&serv->inst, "GET", NULL, "/*", 100,
            &callback_static, root);
    /* Add the key download endpoint. */
    /* Add the key upload endpoint. */
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
