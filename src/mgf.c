#include <string.h>
#ifdef WIN32
#include <stdint.h>
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "encparams.h"
#include "poly.h"

void ntru_MGF(uint8_t *seed, uint16_t seed_len, NtruEncParams *params, NtruIntPoly *i) {
    uint16_t N = params->N;
    i->N = N;
    uint16_t min_calls_mask = params->min_calls_mask;
    uint16_t hlen = params->hlen;

    uint8_t buf[min_calls_mask * hlen];
    uint16_t buf_len = 0;
    uint8_t Z[hlen];
    params->hash(seed, seed_len, (uint8_t*)&Z);   /* hashSeed is always true */
    uint16_t counter = 0;
    uint8_t H[hlen];
    uint16_t inp_len = hlen + sizeof counter;
    uint8_t hash_inp[inp_len];
    while (counter < min_calls_mask) {
        uint16_t counter_endian = htons(counter);   /* convert to network byte order */
        memcpy(&hash_inp, Z, sizeof Z);
        memcpy((uint8_t*)&hash_inp + sizeof Z, &counter_endian, sizeof counter_endian);
        params->hash((uint8_t*)&hash_inp, inp_len, (uint8_t*)&H);

        memcpy(buf+buf_len, H, hlen);
        buf_len += hlen;
        counter++;
    }

    for (;;) {
        uint16_t cur = 0;

        uint16_t j;
        for (j=0; j<buf_len; j++) {
            uint8_t O = buf[j];
            if (O >= 243)   /* 243 = 3^5 */
                continue;

            uint8_t ter_idx;
            for (ter_idx=0; ter_idx<4; ter_idx++) {
                uint8_t rem3 = O % 3;
                i->coeffs[cur] = rem3==2 ? -1 : rem3;   /* reduce to [-1..1] */
                cur++;
                if (cur == N)
                    return;
                O = (O-rem3) / 3;
            }

            i->coeffs[cur] = O==2 ? -1 : O;   /* reduce to [-1..1] */
            cur++;
            if (cur == N)
                return;
        }

        if (cur >= N)
            return;

        memcpy(&hash_inp, Z, sizeof Z);
        memcpy((uint8_t*)&hash_inp + hlen, &counter, sizeof counter);
        params->hash((uint8_t*)&hash_inp, inp_len, (uint8_t*)&H);
        memcpy(&buf, &H, hlen);
        buf_len = hlen;
    }
}
