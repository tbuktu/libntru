#include "encparams.h"
#include "arith.h"

uint16_t ntru_enc_len(NtruEncParams *params) {
    return ntru_enc_len_Nq(params->N, params->q);
}

uint16_t ntru_enc_len_Nq(uint16_t N, uint16_t q) {
    /* make sure q is a power of 2 */
    if (q & (q-1))
        return -1;

    uint16_t len_bits = N * ntru_log2(q);
    uint16_t len_bytes = (len_bits+7) / 8;
    return len_bytes;
}
