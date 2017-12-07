#ifndef SERV_H_
#define SERV_H_

#include <ulfius.h>
#include "keydb.h"

struct serv_state_t;

struct serv_state_t *
start_server(short port, char *root, struct keydb_t *db);

void
stop_server(struct serv_state_t *serv);

#endif
