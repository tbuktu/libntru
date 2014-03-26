#ifndef NTRU_ENCPARAMS_H
#define NTRU_ENCPARAMS_H

#include <stdint.h>
#include "hash.h"

/* max hash output length in bytes */
#define NTRU_MAX_HASH_LEN 64

/** upper limit for the parameter c in NtruEncParams */
#define NTRU_MAX_C 32

/** max length of a bit string in bytes */
#define NTRU_MAX_BIT_STR_LEN (NTRU_MAX_HASH_LEN * (NTRU_MAX_C+1))

/* A set of parameters for NtruEncrypt */
typedef struct NtruEncParams {
    /* number of polynomial coefficients */
    uint16_t N;

    /* modulus */
    uint16_t q;

    /* 1 for product-form private keys, 0 for ternary */
    uint8_t prod_flag;

    /*
     * number of ones in the private polynomial f1 (if prod=1) or f (if prod=0)
     */
    uint16_t df1;

    /*
     * number of ones in the private polynomial f2; ignored if prod=0
     */
    uint16_t df2;

    /*
     * number of ones in the private polynomial f3; ignored if prod=0
     */
    uint16_t df3;

    /*
     * minimum acceptable number of -1's, 0's, and 1's in the polynomial m'
     * in the last encryption step
     */
    uint16_t dm0;

    /*
     * Maximum absolute value of sum_coeffs(mtrin) or zero to disable this check.
     * Values greater than zero cause the constant coefficient of the message to always be zero.
     */
    uint16_t maxm1;

    /* number of random bits to prepend to the message */
    uint16_t db;

    /* a parameter for the Index Generation Function */
    uint16_t c;

    /* minimum number of hash calls for the IGF to make */
    uint16_t min_calls_r;

    /* minimum number of calls to generate the masking polynomial */
    uint16_t min_calls_mask;

    /*
     * whether to hash the seed in the MGF first (1) or
     * use the seed directly (0)
     */
    uint8_t hash_seed;

    /* three bytes that uniquely identify the parameter set */
    uint8_t oid[3];

    /*
     * whether to treat ternary polynomials as sparsely populated (1) or
     * densely (0)
     */
    uint8_t sparse;

    /* hash function, e.g. ntru_sha256 */
    void (*hash)(uint8_t[], uint16_t, uint8_t[]);

    /* output length of the hash function */
    uint16_t hlen;
} NtruEncParams;

/*
 * A parameter set from IEEE 1361.1 that gives 256 bits of security and is optimized for key size.
 */
#define EES1087EP2 {1087, 2048, 0, 120, 0, 0, 120, 0, 256, 13, 25, 14, 1, {0, 6, 3}, 1, ntru_sha512, 64}

/*
 * A conservative (in terms of security) parameter set that gives 256 bits of
 * security and is a tradeoff between key size and encryption/decryption speed.
 */
#define EES1171EP1 {1171, 2048, 0, 79, 0, 0, 106, 0, 256, 13, 20, 15, 1, {0, 6, 4}, 1, ntru_sha512, 64}

/*
 * A conservative (in terms of security) parameter set that gives 256 bits of
 * security and is optimized for encryption/decryption speed.
 */
#define EES1499EP1 {1499, 2048, 0, 79, 0, 0, 79, 0, 256, 13, 17, 19, 1, {0, 6, 5}, 1, ntru_sha512, 64}

/*
 * A parameter set that gives 128 bits of security.
 */
#define APR2011_439_FAST {439, 2048, 1, 9, 8, 5, 130, 126, 128, 12, 32, 9, 1, {0, 7, 101}, 1, ntru_sha256, 32}

/*
 * A parameter set that gives 256 bits of security.
 */
#define APR2011_743_FAST {743, 2048, 1, 11, 11, 15, 220, 60, 256, 12, 27, 14, 1, {0, 7, 105}, 0, ntru_sha512, 64}

uint16_t ntru_enc_len(uint16_t N, uint16_t q);

#endif   /* NTRU_ENCPARAMS_H */
