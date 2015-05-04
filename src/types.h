#ifndef NTRU_TYPES_H
#define NTRU_TYPES_H

#include <stdint.h>

#define NTRU_MAX_DEGREE (1499+1)   /* max N value for all param sets; +1 for ntru_invert_...() */
#define NTRU_INT_POLY_SIZE ((NTRU_MAX_DEGREE+16+7)&0xFFF8)   /* (max #coefficients + 16) rounded to a multiple of 8 */
#define NTRU_MAX_ONES 499   /* max(df1, df2, df3, dg) */

/** A polynomial with integer coefficients. */
typedef struct NtruIntPoly {
    uint16_t N;
    int16_t coeffs[NTRU_INT_POLY_SIZE];
} NtruIntPoly;

/** A ternary polynomial, i.e. all coefficients are equal to -1, 0, or 1. */
typedef struct NtruTernPoly {
    uint16_t N;
    uint16_t num_ones;
    uint16_t num_neg_ones;
    uint16_t ones[NTRU_MAX_ONES];
    uint16_t neg_ones[NTRU_MAX_ONES];
} NtruTernPoly;

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
/**
 * A product-form polynomial, i.e. a polynomial of the form f1*f2+f3
 * where f1,f2,f3 are very sparsely populated ternary polynomials.
 */
typedef struct NtruProdPoly {
    uint16_t N;
    NtruTernPoly f1, f2, f3;
} NtruProdPoly;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

/** Private polynomial, can be ternary or product-form */
typedef struct {
    uint8_t prod_flag;   /* whether the polynomial is in product form */
    union {
        NtruTernPoly tern;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
        NtruProdPoly prod;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    } poly;
} NtruPrivPoly;

/**
 * NtruEncrypt private key
 */
typedef struct NtruEncPrivKey {
    uint16_t q;
    NtruPrivPoly t;
} NtruEncPrivKey;

/**
 * NtruEncrypt public key
 */
typedef struct NtruEncPubKey {
    uint16_t q;
    NtruIntPoly h;
} NtruEncPubKey;

/**
 * NtruEncrypt key pair
 */
typedef struct NtruEncKeyPair {
    NtruEncPrivKey priv;
    NtruEncPubKey pub;
} NtruEncKeyPair;
#endif   /* NTRU_TYPES_H */
