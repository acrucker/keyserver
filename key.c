#include "key.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

#include <openssl/sha.h>

#define RD_BYTE(v, f) \
    if (1 != fread(&v, sizeof(uint8_t), 1, f)) \
        return -1;

#define START_ASCII "-----BEGIN PGP PUBLIC KEY BLOCK-----"
#define END_ASCII "-----END PGP PUBLIC KEY BLOCK-----"

struct pgp_key_t *
alloc_key() {
    struct pgp_key_t *ret;
    ret = malloc(sizeof(*ret));
    if (!ret) return NULL;

    memset(ret, 0, sizeof(*ret));
    return ret;
}

void
inner_free_key(struct pgp_key_t *key) {
    if (!key) return;
    if (key->user_id) free(key->user_id);
    if (key->data) free(key->data);
    memset(key, 0, sizeof(*key));
}

void
deep_free_key(struct pgp_key_t *key) {
    inner_free_key(key);
    free(key);
}

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

int
get_key_id(uint8_t *pkt, uint64_t pkt_len, int *v, fp160 fp, uint32_t *id32, uint64_t *id64) {
    uint8_t *buf;
    int ret, i;
    uint64_t tmp;

    ret = 0;
    tmp = 0;
    buf = malloc((pkt_len+3)*sizeof(uint8_t));
    if (!buf)
        return -1;

    switch (pkt[0]) {
        /* v3 keys are too old to require support. */
        case 3:
            memset(fp, 0, sizeof(fp160));
            ret = -1;
            break;
        /* Key ID is calculated through hashing. */
        case 4:
            buf[0] = 0x99;
            buf[1] = (pkt_len&0xFF00)>>8;
            buf[2] = pkt_len&0xFF;
            memcpy(&buf[3], pkt, pkt_len);
            SHA1(buf, pkt_len+3, fp);
            for (i=12; i<20; i++) {
                tmp <<= 8;
                tmp |= fp[i];
            }
            *v = 4;
            break;
        default:
            ret = -1;
    }

    *id64 = tmp;
    *id32 = tmp&0xFFFFFFFF;

    free(buf);
    return ret;
}

void
pretty_print_key(struct pgp_key_t *key, char *prefix) {
    int i;

    printf("%sPGP key (v%d, length %lu octets)\n", prefix, key->version, key->len);
    printf("%s\t   H: ", prefix);
    for (i=0; i<20; i++)
        printf("%02X", key->hash[i]);
    printf("\n%s\t  FP: ", prefix);
    for (i=0; i<20; i++)
        printf("%02X", key->fp[i]);
    printf("\n%s\tID64: %016lX\n%s\tID32: %08X\n", prefix, key->id64, prefix, key->id32);
    printf("%s\t UID: %s\n", prefix, key->user_id);
}

int
parse_key_metadata(struct pgp_key_t *key) {
    uint8_t *pkt_ptr;
    uint8_t hdr_len;
    uint8_t type;
    uint64_t pkt_len;
    uint64_t offset;

    offset = 0;

    /* Make a hash of the entire key */
    SHA1(key->data, key->len, key->hash);

    key->user_id = 0;

    while (!parse_packet_header(key->data+offset, &hdr_len, &type, &pkt_len)) {
        /* Packets can't extend beyond the end of the key's data. */
        if (offset+hdr_len+pkt_len > key->len)
            goto error;

        /* Pointer to the first byte of the packet. */
        pkt_ptr = key->data+offset+hdr_len;

        switch (type) {
        /* Public key packet. */
        case 6:
            if (get_key_id(pkt_ptr, pkt_len, &key->version, key->fp, 
                        &key->id32, &key->id64)) goto error;;
            break;
        /* User ID packet. */
        case 13:
            if (key->user_id) break;
            if (!(key->user_id = malloc((pkt_len+1)*sizeof(uint8_t)))) goto error;;
            memcpy(key->user_id, pkt_ptr, pkt_len*sizeof(uint8_t));
            key->user_id[pkt_len] = '\0';
            break;
        /* Will skip most packets. */
        default:
            break;
        }

        offset += hdr_len + pkt_len;
        if (offset == key->len)
            break;
    }

    if (!key->user_id)
        key->user_id = strdup("");

    if (!key->user_id)
        goto error;

    key->analyzed = 1;
    return 0;
error:
    free(key->user_id);
    return -1;
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
        goto error;

    if (key->len != fread(key->data, 1, key->len, in))
        goto error;

    return 0;
error:
    inner_free_key(key);
    return -1;
}

void
ascii_armor_24b(uint32_t val, char enc[5]) {
    int j;

    for (j=3; j>=0; j--) {
        enc[j] = val&0x3F;
        val >>= 6;  /* IBM doesn't deserve nice things. */
        if (enc[j] < 26)      enc[j] = 'A'+enc[j];
        else if (enc[j] < 52) enc[j] = 'a'+(enc[j]-26);
        else if (enc[j] < 62) enc[j] = '0'+(enc[j]-52);
        else if (enc[j] < 63) enc[j] = '+';
        else                  enc[j] = '/';
    }
}

/* Adapted from the implementation on Page 54 of RFC 4880. */
#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

long crc_octets(unsigned char *octets, size_t len)
{
    long crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFL;
}

char *
ascii_armor_keys(struct pgp_key_t *key, int count) {
    char *buf;
    uint8_t *data;
    int line_written, i;
    int printed;
    size_t total_len;
    uint32_t tmp;
    char enc[5];
    
    total_len = 0;
    for (i=0; i<count; i++)
        total_len += key[i].len;
    data = malloc(total_len);
    buf = malloc(total_len*2+1024);
    if (!buf) goto error;
    if (!data) goto error;
    total_len = 0;
    for (i=0; i<count; i++) {
        memcpy(data+total_len, key[i].data, key[i].len);
        total_len += key[i].len;
    }

    line_written = 0;
    enc[4] = 0;
    printed = 0;

    printed += sprintf(buf+printed, START_ASCII "\n\n");
    for (i=0; i<total_len; i+=3) {
        if (line_written == 64) {
            line_written = 0;
            printed += sprintf(buf+printed, "\n");
        }
        if (i+2 < total_len)
            tmp = (data[i]<<16) | (data[i+1]<<8) | (data[i+2]);
        else if (i+2 == total_len)
            tmp = (data[i]<<16) | (data[i+1]<<8);
        else if (i+1 == total_len)
            tmp = (data[i]<<16);

        ascii_armor_24b(tmp, enc);

        if (i+2 == total_len)
            enc[3] = '=';
        else if (i+1 == total_len)
            enc[2] = enc[3] = '=';

        printed += sprintf(buf+printed, "%s", enc);
        line_written += 4;
    }
    tmp = crc_octets(data, total_len);
    ascii_armor_24b(tmp, enc);
    printed += sprintf(buf+printed, "\n=%s", enc);
    printed += sprintf(buf+printed, "\n" END_ASCII);
    free(data);
    return buf;
error:
    if (buf)
        free(buf);
    if (data)
        free(data);
    return NULL;
}

int
r64_decode(char c) {
    if (isupper(c))
        return c-'A';
    else if (islower(c))
        return c-'a'+26;
    else if (isdigit(c))
        return c-'0'+52;
    else if (c == '+')
        return 62;
    else if (c == '/')
        return 63;
    else
        assert(0);
}

int
ascii_parse_key(const char *buf, struct pgp_key_t *key) {
    int consec_nl;
    int n_ascii_ch, n_pad, n_crc;
    int tmp_cnt;
    int data_pos;
    char c;
    const char *bulk_start, *crc_start;
    uint32_t tmp;
    key->data = NULL;
    /* Start by verifying that buf conforms to ASCII-armor spec; get len.*/
    if (strstr(buf, START_ASCII) != buf) goto error;
    buf += strlen(START_ASCII);
    /* Look for two line endings with no intervening non-whitespace */
    consec_nl = 0;
    while ((c = *buf++)) {
        switch (c) {
            case '\n':
                consec_nl++;
                break;
            default:
                if (!isspace(c))
                    consec_nl = 0;
                break;
        }
        if (consec_nl == 2)
            break;
    }
    if (!c) goto error;
    /* Now count the number of characters in the buffer. */
    n_ascii_ch = n_pad = 0;
    bulk_start = buf;
    while ((c = *buf++)) {
        if (isspace(c))
            continue;
        else if (isalnum(c) || c == '/' || c == '+')
            n_ascii_ch++;
        else if (c == '=') {
            if ((n_ascii_ch+n_pad)%4)
                n_pad++;
            else
                /* This is the pre-CRC = */
                break;
        } else {
            goto error;
        }
    }
    if (!c) goto error;
    /* Now count the number of characters in the crc. */
    n_crc = 0;
    crc_start = buf;
    while ((c = *buf++)) {
        if (isspace(c))
            continue;
        else if (isalnum(c) || c == '/' || c == '+')
            n_crc++;
        else if (c == '-') {
            buf--;
            /* This is the ending line*/
            break;
        } else {
            goto error;
        }
    }
    if (!c) goto error;
    if (strstr(buf, END_ASCII) != buf) goto error;
    if (n_crc != 4) goto error;
    if ((n_ascii_ch+n_pad)%4 != 0) goto error;
    if (n_pad > 2) goto error;

    /* Start the actual parsing. */
    key->len = 3*(n_ascii_ch+n_pad)/4-n_pad;
    if (!(key->data = malloc(key->len))) goto error;
    tmp_cnt = 0;
    data_pos = 0;

    while ((c = *bulk_start++)) {
        if (isspace(c))
            continue;
        if (isalnum(c) || c == '/' || c == '+') {
            tmp <<= 6;
            tmp |= r64_decode(c);
            tmp_cnt++;
        }
        if (c == '=') {
            if (tmp_cnt == 2)
                tmp <<= 12;
            else if (tmp_cnt == 3)
                tmp <<= 6;
            else 
                goto error;
            tmp_cnt = 4;
        }
        if (tmp_cnt == 4) {
            if (data_pos+2 < key->len)
                key->data[data_pos+2] = tmp&0xFF;
            if (data_pos+1 < key->len)
                key->data[data_pos+1] = (tmp>>8)&0xFF;
            assert(data_pos < key->len);
            key->data[data_pos] = (tmp>>16)&0xFF;
            data_pos += 3;
            tmp = 0;
            tmp_cnt = 0;
        }
        if (data_pos >= key->len)
            break;
    }
    while ((c = *crc_start++)) {
        if (isspace(c))
            continue;
        if (isalnum(c) || c == '/' || c == '+') {
            tmp <<= 6;
            tmp |= r64_decode(c);
            tmp_cnt++;
        }
        if (tmp_cnt == 4) {
            if (tmp != crc_octets(key->data, key->len))
                goto error;
            break;
        }
    }
    return 0;
error:
    if (key->data)
        free(key->data);
    return -1;
}

