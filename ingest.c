#include <stdio.h>
#include <stdlib.h>
#include "key.h"

int main(int argc, char **argv) {
    FILE *in;
    struct pgp_key_t key;
    int read;

    read = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./ingest <dump-file>\n");
        exit(1);
    }
    in = fopen(argv[1], "rb");
    if (!in) {
        fprintf(stderr, "Could not open dump file %s\n", argv[1]);
        exit(1);
    }
    
    while (!parse_from_dump(in, &key)) {
        printf("Read a key of length %lu.\n", key.len);
        free(key.data);
        read++;
    }
    printf("Read %d keys.\n", read);
    return 0;
}
