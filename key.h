#ifndef KEY_H_
#define KEY_H_

#include "types.h"
#include <stdio.h>

struct pgp_key_t *
alloc_key();

void
free_key(struct pgp_key_t *key);

void
inner_free_key(struct pgp_key_t *key);

/* Attempts to parse a public key from a file dump. Returns 0 on success and
 * non-zero on failure. On a successful return, the value pointed to by key is 
 * filled in with the results. */
int
parse_from_dump(FILE *in, struct pgp_key_t *key);

/* Pretty prints a key to standard out with an optional prefix. */
void
pretty_print_key(struct pgp_key_t *key, char *prefix);

/* Parses a raw key to isolate metadata. */
int
parse_key_metadata(struct pgp_key_t *key);

/* Produces the ASCII-armor representation of a public keyring. */
char *
ascii_armor_keys(struct pgp_key_t *key, int count);

/* Attempts to parse an ASCII-armored key. */
int
ascii_parse_key(const char *buf, struct pgp_key_t *key);

#endif
