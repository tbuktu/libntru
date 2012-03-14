#ifndef ENCPARAMS_H
#define ENCPARAMS_H

#include "hash.h"

/* max hash output length in bytes */
#define NTRU_MAX_HASH_LEN 64

/** upper limit for the parameter c in NtruEncParams */
#define NTRU_MAX_C 32

/** max length of a bit string in bytes */
#define NTRU_MAX_BIT_STR_LEN (NTRU_MAX_HASH_LEN * (NTRU_MAX_C+1))

/* A set of parameters for NtruEncrypt */
struct NtruEncParams {
    /* number of polynomial coefficients */
    int N;

    /* modulus */
    int q;

    /*
     * number of ones in the private polynomial f1
     */
    int df1;

    /*
     * number of ones in the private polynomial f2
     */
    int df2;

    /*
     * number of ones in the private polynomial f3
     */
    int df3;

    /*
     * minimum acceptable number of -1's, 0's, and 1's in the polynomial m'
     * in the last encryption step
     */
    int dm0;

    /* number of random bits to prepend to the message */
    int db;

    /* a parameter for the Index Generation Function */
    int c;

    /* minimum number of hash calls for the IGF to make */
    int min_calls_r;

    /* minimum number of calls to generate the masking polynomial */
    int min_calls_mask;

    /*
     * whether to hash the seed in the MGF first (1) or
     * use the seed directly (0)
     */
    int hash_seed;

    /* three bytes that uniquely identify the parameter set */
    char oid[3];

    /*
     * whether to treat ternary polynomials as sparsely populated (1) or
     * densely (0)
     */
    int sparse;

    /* hash function, e.g. ntru_sha256 */
    void (*hash)(char[], int, char[]);

    /* output length of the hash function */
    int hlen;
};
extern struct NtruEncParams NtruEncParams;

/*
 * A conservative (in terms of security) parameter set that gives 256 bits of
 * security and is optimized for key size.
 */
#define EES1087EP2_FAST {1087, 2048, 8, 8, 8, 120, 256, 13, 25, 14, 1, {0, 6, 3}, 1, ntru_sha512, 64}

/*
 * A conservative (in terms of security) parameter set that gives 256 bits of
 * security and is a tradeoff between key size and encryption/decryption speed.
 */
#define EES1171EP1_FAST {1171, 2048, 8, 7, 7, 106, 256, 13, 20, 15, 1, {0, 6, 4}, 1, ntru_sha512, 64}

/*
 * A conservative (in terms of security) parameter set that gives 256 bits of
 * security and is optimized for encryption/decryption speed.
 */
#define EES1499EP1_FAST = {1499, 2048, 7, 6, 6, 79, 256, 13, 17, 19, 1, {0, 6, 5}, 1, ntru_sha512, 64}

/*
 * A parameter set that gives 128 bits of security.
 */
#define APR2011_439_FAST {439, 2048, 9, 8, 5, 130, 128, 9, 32, 9, 1, {0, 7, 101}, 1, ntru_sha256, 32}

/*
 * A parameter set that gives 256 bits of security.
 */
#define APR2011_743_FAST {743, 2048, 11, 11, 15, 220, 256, 10, 27, 14, 1, {0, 7, 105}, 0, ntru_sha512, 64}

#endif   /* ENCPARAMS_H */
