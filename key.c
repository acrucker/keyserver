#include "key.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define RD_BYTE(v, f) \
    if (1 != fread(&v, sizeof(uint8_t), 1, f)) \
        return -1;

uint64_t
rd_n_bytes(FILE *in, int n) {
    uint8_t tmp;
    uint64_t ret;
    assert(0 <= n && n <= 7);
    ret = 0;
    for(; n; n--) {
        RD_BYTE(tmp, in);
        ret <<= 8;
        ret |= tmp;
    }
    return ret;
}

uint64_t
get_new_pkt_len(FILE *in) {
    uint8_t tmp;
    uint32_t pkt_len;
    RD_BYTE(tmp, in);
    if (tmp < 192) {
        pkt_len = tmp;
    } else if (tmp < 224) {
        pkt_len = (tmp-192)<<8;
        RD_BYTE(tmp, in);
        pkt_len |= tmp + 192;
    } else if (tmp == 255) {
        pkt_len = rd_n_bytes(in, 4);
    } else {
        return -1;
    }
    return pkt_len;
}

uint64_t
get_old_pkt_len(FILE *in, uint8_t len_type) {
    switch(len_type) {
        case 0:
            return rd_n_bytes(in, 1);
        case 1:
            return rd_n_bytes(in, 2);
        case 2:
            return rd_n_bytes(in, 4);
        case 3:
        default:
            return -1;
    }
}

int
parse_from_dump(FILE *in, struct pgp_key_t *key) {
    int tmp;
    uint8_t type;
    char started, new;
    size_t start_pos, end_pos;
    size_t pkt_len;

    start_pos = ftell(in);
    started = 0;

    do {
        end_pos = ftell(in);
        tmp = fgetc(in);

        if (tmp == EOF) {
            if (started)
                break;
            else
                return -1;
        }

        if (!(tmp&0x80))
            return -1;

        new = tmp&0x40;
        if (new)
            type = tmp&0x3F;
        else
            type = (tmp>>2)&0xF;

        /*printf("Skipping packet (tag 0x%X) of type %d.\n", tmp, type);*/

        if (type == 6) {
            /*printf("Packet is a public key packet.\n");*/
            if (started)
                break;
            started = 1;
        }
        if (new) {
            pkt_len = get_new_pkt_len(in);
            /*printf("Packet is a new format packet of length %lu.\n", pkt_len);*/
        } else {
            pkt_len = get_old_pkt_len(in, tmp&0x3);
            /*printf("Packet is a old format packet of length %lu.\n", pkt_len);*/
        }
        /* Skip the remainder of the packet. */
        fseek(in, pkt_len, SEEK_CUR);
    } while (1);

    assert(!fseek(in, start_pos, SEEK_SET));
    key->len = end_pos-start_pos;
    key->data = malloc(key->len);
    if (!key->data)
        return -1;

    if (key->len != fread(key->data, 1, key->len, in)) {
        key->len = 0;
        free(key->data);
        key->data = NULL;
        return -1;
    }

    return 0;
}

    

        


