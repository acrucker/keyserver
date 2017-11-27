#ifndef _KEY_H
#define _KEY_H

#include "types.h"
#include <stdio.h>

/* Attempts to parse a public key from a file dump. Returns 0 on success and
 * non-zero on failure. On a successful return, the value pointed to by key is 
 * filled in with the results. */
int
parse_from_dump(FILE *in, struct pgp_key_t *key);

#endif
