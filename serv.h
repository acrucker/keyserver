#ifndef _SERV_H
#define _SERV_H

#include <ulfius.h>

struct serv_state_t;

struct serv_state_t *
start_server(short port, char *root);

void
stop_server(struct serv_state_t *serv);

#endif
