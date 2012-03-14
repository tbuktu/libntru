#include <string.h>
#include <netinet/in.h>
#include "encparams.h"
#include "poly.h"

void ntru_MGF(char *seed, int seed_len, struct NtruEncParams *params, NtruIntPoly *i) {
    int N = params->N;
    i->N = N;
    int min_calls_mask = params->min_calls_mask;
    int hlen = params->hlen;

    char buf[min_calls_mask * hlen];
    int buf_len = 0;
    char Z[hlen];
    params->hash(seed, seed_len, (char*)&Z);   /* hashSeed is always true */
    int counter = 0;
    char H[hlen];
    int inp_len = hlen + sizeof counter;
    char hash_inp[inp_len];
    while (counter < min_calls_mask) {
        int counter_endian = htonl(counter);   /* convert to network byte order */
        memcpy(&hash_inp, Z, sizeof Z);
        memcpy((char*)&hash_inp + sizeof Z, &counter_endian, sizeof counter_endian);
        params->hash((char*)&hash_inp, inp_len, (char*)&H);

        memcpy(buf+buf_len, H, hlen);
        buf_len += hlen;
        counter++;
    }

    for (;;) {
        int cur = 0;

        int j;
        for (j=0; j<buf_len; j++) {
            int O = (unsigned char)buf[j];
            if (O >= 243)   /* 243 = 3^5 */
                continue;

            int ter_idx;
            for (ter_idx=0; ter_idx<4; ter_idx++) {
                int rem3 = O % 3;
                i->coeffs[cur] = rem3 - 1;
                cur++;
                if (cur == N)
                    return;
                O = (O-rem3) / 3;
            }

            i->coeffs[cur] = O - 1;
            cur++;
            if (cur == N)
                return;
        }

        if (cur >= N)
            return;

        memcpy(&hash_inp, (char*)Z, sizeof Z);
        memcpy((char*)&hash_inp + hlen, &counter, sizeof counter);
        params->hash((char*)&hash_inp, inp_len, (char*)&H);
        memcpy(&buf, &H, hlen);
        buf_len = hlen;
    }
}
