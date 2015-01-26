#include <string.h>
#include "idxgen.h"

void ntru_IGF_init(uint8_t *seed, uint16_t seed_len, NtruEncParams *params, NtruIGFState *s) {
    s->Z = seed;
    s->zlen = seed_len;
    s->N = params->N;
    s->c = params->c;
    s->rnd_thresh = (1<<s->c) - (1<<s->c)%s->N;
    s->hlen = params->hlen;
    s->rem_len = params->min_calls_r * 8 * s->hlen;
    s->hash = params->hash;
    s->counter = 0;

    s->buf.num_bytes = 0;
    s->buf.last_byte_bits = 0;

    uint8_t H[NTRU_MAX_HASH_LEN];

    while (s->counter < params->min_calls_r) {
        uint16_t inp_len = s->zlen + sizeof s->counter;
        uint8_t hash_inp[inp_len];
        memcpy(&hash_inp, (uint8_t*)s->Z, s->zlen);
        memcpy((uint8_t*)&hash_inp + s->zlen, &s->counter, sizeof s->counter);
        s->hash((uint8_t*)&hash_inp, inp_len, (uint8_t*)&H);

        ntru_append(&s->buf, (uint8_t*)&H, s->hlen);
        s->counter++;
    }
}

void ntru_IGF_next(NtruIGFState *s, uint16_t *i) {
    uint16_t N = s-> N;
    uint16_t c = s-> c;

    uint8_t H[NTRU_MAX_HASH_LEN];

    for (;;) {
        if (s->rem_len < c) {
            NtruBitStr M;
            ntru_trailing(&s->buf, s->rem_len, &M);
            uint16_t tmp_len = c - s->rem_len;
            uint16_t c_thresh = s->counter + (tmp_len+s->hlen-1) / s->hlen;
            while (s->counter < c_thresh) {
                uint16_t inp_len = s->zlen + sizeof s->counter;
                uint8_t hash_inp[inp_len];
                memcpy(&hash_inp, (uint8_t*)s->Z, s->zlen);
                memcpy((uint8_t*)&hash_inp + s->zlen, &s->counter, sizeof s->counter);
                s->hash((uint8_t*)&hash_inp, inp_len, (uint8_t*)&H);

                ntru_append(&M, (uint8_t*)&H, s->hlen);
                s->counter++;
                s->rem_len += 8 * s->hlen;
            }
            s->buf = M;
        }

        *i = ntru_leading(&s->buf, c);   /* assume c<32 */
        ntru_truncate(&s->buf, c);
        s->rem_len -= c;
        if (*i < s->rnd_thresh) {   /* if (*i < (1<<c)-(1<<c)%N) */
            while (*i >= N)
                *i -= N;
            return;
        }
    }
}
