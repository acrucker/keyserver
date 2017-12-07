#ifndef UTIL_H_
#define UTIL_H_

#include "types.h"

void
parse_fp160(const char *buf, fp160 out);

/* Returns zero iff a == b. */
int
neq_fp160(fp160 a, fp160 b);

#endif
