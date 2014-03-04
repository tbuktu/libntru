#ifndef IDXGEN_H
#define IDXGEN_H

#include "encparams.h"
#include "bitstring.h"

typedef struct NtruIGFState {
    int N;
    int c;
    char *Z;
    int zlen;
    int rem_len;
    NtruBitStr buf;
    int counter;
    void (*hash)(char[], int, char[]);
    int hlen;
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
void ntru_IGF_init(char *seed, int seed_len, NtruEncParams *params, NtruIGFState *s);

/**
 * @brief IGF next index
 *
 * Returns the next index.
 * Based on IGF-2 from IEEE P1363.1 section 8.4.2.1.
 *
 * @param s
 * @param i
 */
void ntru_IGF_next(NtruIGFState *s, int *i);

#endif   /* IDXGEN_H */
