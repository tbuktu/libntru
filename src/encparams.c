#include "encparams.h"

int ntru_enc_len(int N, int q) {
    /* make sure q is a power of 2 */
    if (q & (q-1))
        return -1;

    int log2q = 0;
    while (q > 1) {
        q /= 2;
        log2q++;
    }

    int len_bits = N * log2q;
    int len_bytes = (len_bits+7) / 8;
    return len_bytes;
}
