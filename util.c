#include "util.h"

void
parse_fp160(const char *buf, fp160 out) {
    char tmp[3];
    int i;
    tmp[2] = 0;

    for (i=0; i<20; i+=1) {
        tmp[0] = buf[2*i];
        tmp[1] = buf[2*i+1];
        out[i] = strtol(tmp, NULL, 16);
    }
}

/* Returns non-zero iff a != b. */
int
neq_fp160(fp160 a, fp160 b) {
    int i;
    int diff;

    diff = 0;
    for (i=0; i<20; i++)
        diff |= a[i]^b[i];

    return diff;
}

