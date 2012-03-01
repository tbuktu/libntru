#include <openssl/sha.h>
#include <string.h>
#include "idxgen.h"

void ntru_IGF_init(char *seed, int seed_len, struct NtruEncParams *params, void (*hash)(char[], int, char[]), NtruIGFState *s) {
    s->Z = seed;
    s->zlen = seed_len;
    s->N = params->N;
    s->c = params->c;
    s->hlen = params->hlen;
    s->rem_len = params->min_calls_r * 8 * s->hlen;
    s->hash = hash;
    s->counter = 0;

    s->buf.num_bytes = 0;
    s->buf.last_byte_bits = 0;

    unsigned char H[NTRU_MAX_HASH_LEN];

    while (s->counter < params->min_calls_r) {
        int inp_len = s->zlen + sizeof s->counter;
        char hash_inp[inp_len];
        memcpy(&hash_inp, (char*)s->Z, s->zlen);
        memcpy((char*)&hash_inp + s->zlen, &s->counter, sizeof s->counter);
        hash((char*)&hash_inp, inp_len, (char*)&H);

        ntru_append(&s->buf, (unsigned char*)&H, s->hlen);
        s->counter++;
    }
}

void ntru_IGF_next(NtruIGFState *s, int *i) {
    int N = s-> N;
    int c = s-> c;

    unsigned char H[NTRU_MAX_HASH_LEN];

    for (;;) {
        if (s->rem_len < c) {
            NtruBitStr M;
            ntru_trailing(&s->buf, s->rem_len, &M);
            int tmp_len = c - s->rem_len;
            int c_thresh = s->counter + (tmp_len+s->hlen-1) / s->hlen;
            while (s->counter < c_thresh) {
                int inp_len = s->zlen + sizeof s->counter;
                unsigned char hash_inp[inp_len];
                memcpy(&hash_inp, (unsigned char*)s->Z, s->zlen);
                memcpy((char*)&hash_inp + s->zlen, &s->counter, sizeof s->counter);
                s->hash((char*)&hash_inp, inp_len, (char*)&H);

                ntru_append(&M, (unsigned char*)&H, s->hlen);
                s->counter++;
                s->rem_len += 8 * s->hlen;
            }
            s->buf = M;
        }

        *i = ntru_leading(&s->buf, c);   /* assume c<32 */
        ntru_truncate(&s->buf, c);
        s->rem_len -= c;
        if (*i < (1<<c)-((1<<c)%N))
            return;
    }
}
