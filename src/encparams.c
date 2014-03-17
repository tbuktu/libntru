#include "encparams.h"

uint16_t ntru_enc_len(uint16_t N, uint16_t q) {
    /* make sure q is a power of 2 */
    if (q & (q-1))
        return -1;

    uint16_t log2q = 0;
    while (q > 1) {
        q /= 2;
        log2q++;
    }

    uint16_t len_bits = N * log2q;
    uint16_t len_bytes = (len_bits+7) / 8;
    return len_bytes;
}
