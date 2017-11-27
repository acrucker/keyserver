#include "key.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/sha.h>

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
parse_packet_header(uint8_t *pkt, 
                    uint8_t *hdr_len, 
                    uint8_t *type,
                    uint64_t *pkt_len) {
    char new;
    if (!(pkt[0]&0x80))
        return -1;

    new = pkt[0]&0x40;
    if (new)
        *type = pkt[0]&0x3F;
    else
        *type = (pkt[0]>>2)&0xF;

    if (new) {
        if (pkt[1] < 192) {
            *hdr_len = 2;
            *pkt_len = pkt[1];
        } else if (pkt[1] < 224) {
            *hdr_len = 3;
            *pkt_len = ((pkt[1]-192)<<8) + pkt[2] + 192;
        } else if (pkt[1] == 255) {
            *hdr_len = 6;
            *pkt_len = (pkt[2]<<24) | (pkt[3]<<16) | (pkt[4]<<8) | pkt[5];
        } else {
            return -1;
        }
    } else {
        switch (pkt[0]&3) {
            case 0:
                *hdr_len = 2;
                *pkt_len = pkt[1];
                break;
            case 1:
                *hdr_len = 3;
                *pkt_len = (pkt[1]<<8) | pkt[2];
                break;
            case 2:
                *hdr_len = 5;
                *pkt_len = (pkt[1]<<24) | (pkt[2]<<16) | (pkt[3]<<8) | pkt[4];
                break;
            case 3:
            default:
                return -1;
        }
    }

    return 0;
}

#if 0
uint64_t
get_key_id(uint8_t *pkt, uint64_t pkt_len) {
    uint8_t *buf;
    uint64_t ret;
    fp160 fp;
    int i;

    buf = malloc((pkt_len+3)*sizeof(uint8_t));
    if (!buf)
        goto error;

    switch (pkt[0]) {
        /* Key ID is the low 64 bits of the public modulus. */
        case 2:
        case 3:
            break;
        /* Key ID is calculated through hashing. */
        case 4:
            buf[0] = 0x99;
            buf[1] = pkt_len&0xFF00>>8;
            buf[2] = pkt_len&0xFF;
            memcpy(&buf[3], pkt, pkt_len);
            SHA1(buf, pkt_len+3, fp);

            ret = 0;
            for(i=0; i<8; i++) {
                ret <<= 8;
                ret |= fp[i];
            }
            break;
        default:
            ret = -1;

    }

    free(buf);
    return ret;
}
#endif

void
pretty_print_key(struct pgp_key_t *key, char *prefix) {
    int i;

    printf("%sPGP key (length %lu octets)\n", prefix, key->len);
    printf("%s\tH: ", prefix);

    for (i=0; i<20; i++)
        printf("%02X", key->hash[i]);
    printf("\n");
}

int
parse_key_metadata(struct pgp_key_t *key) {
    /*uint8_t *pkt_ptr;*/
    uint8_t hdr_len;
    uint8_t type;
    uint64_t pkt_len;
    uint64_t offset;

    offset = 0;

    /* Make a hash of the entire key */
    SHA1(key->data, key->len, key->hash);

    while (!parse_packet_header(key->data+offset, &hdr_len, &type, &pkt_len)) {
        /* Packets can't extend beyond the end of the key's data. */
        if (offset+hdr_len+pkt_len > key->len)
            return -1;

        /* Pointer to the first byte of the packet. */
        /*pkt_ptr = key->data+offset+hdr_len;*/

        switch (type) {
        /* Public key packet. */
        case 6:
            /*key->fp = get_key_id(pubkey_pkt, pkt_len); */
            break;
        /* User ID packet. */
        case 13:
            break;
        /* Will skip most packets. */
        default:
            break;
        }

        offset += hdr_len + pkt_len;
        if (offset == key->len)
            break;
    }

    return 0;
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

    return parse_key_metadata(key);
}

