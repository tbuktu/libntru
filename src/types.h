#ifndef TYPES_H
#define TYPES_H

#define NTRU_MAX_N 1500   /* must be one higher than the maximum #coeffs */
#define NTRU_MAX_ONES 499   /* max(df1, df2, df3, dg) */

/** A polynomial with integer coefficients. */
typedef struct NtruIntPoly {
    int N;
    int coeffs[NTRU_MAX_N];
} NtruIntPoly;

/** A ternary polynomial, i.e. all coefficients are equal to -1, 0, or 1. */
typedef struct NtruTernPoly {
    int N;
    int num_ones;
    int num_neg_ones;
    int ones[NTRU_MAX_ONES];
    int neg_ones[NTRU_MAX_ONES];
} NtruTernPoly;

/**
 * A product-form polynomial, i.e. a polynomial of the form f1*f2+f3
 * where f1,f2,f3 are very sparsely populated ternary polynomials.
 */
typedef struct NtruProdPoly {
    int N;
    NtruTernPoly f1, f2, f3;
} NtruProdPoly;

/**
 * NtruEncrypt private key
 */
typedef struct NtruEncPrivKey {
    int q;
    NtruProdPoly t;
} NtruEncPrivKey;

/**
 * NtruEncrypt public key
 */
typedef struct NtruEncPubKey {
    int q;
    NtruIntPoly h;
} NtruEncPubKey;

/**
 * NtruEncrypt key pair
 */
typedef struct NtruEncKeyPair {
    NtruEncPrivKey priv;
    NtruEncPubKey pub;
} NtruEncKeyPair;

/**
 * Seed and state for deterministic random number generators
 */
typedef struct NtruRandContext {
    char *seed;
    int seed_len;
    void **rand_state;
} NtruRandContext;

#endif
