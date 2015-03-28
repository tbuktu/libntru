#ifndef NTRU_IDXGEN_H
#define NTRU_IDXGEN_H

#include <stdint.h>
#include "encparams.h"
#include "bitstring.h"

typedef struct NtruIGFState {
    uint16_t N;
    uint16_t c;
    uint16_t rnd_thresh;   /* value below which random numbers are accepted */
    uint8_t *Z;
    uint16_t zlen;
    uint16_t rem_len;
    NtruBitStr buf;
    uint16_t counter;
    void (*hash)(uint8_t[], uint16_t, uint8_t[]);
    void (*hash_4way)(uint8_t*[4], uint16_t, uint8_t*[4]);
    uint16_t hlen;
} NtruIGFState;

/**
 * @brief IGF initialization
 *
 * Initializes the Index Generation Function.
 * Based on IGF-2 from IEEE P1363.1 section 8.4.2.1.
 *
 * @param seed
 * @param seed_len
 * @param params
 * @param s
 */
void ntru_IGF_init(uint8_t *seed, uint16_t seed_len, NtruEncParams *params, NtruIGFState *s);

/**
 * @brief IGF next index
 *
 * Returns the next index.
 * Based on IGF-2 from IEEE P1363.1 section 8.4.2.1.
 *
 * @param s
 * @param i
 */
void ntru_IGF_next(NtruIGFState *s, uint16_t *i);

#endif   /* NTRU_IDXGEN_H */
