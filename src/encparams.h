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
    /* name of the parameter set */
    char name[11];

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
     * number of ones in the polynomial g (used during key generation)
     */
    uint16_t dg;

    /*
     * minimum acceptable number of -1's, 0's, and 1's in the polynomial m'
     * in the last encryption step
     */
    uint16_t dm0;

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

    /* hash function, e.g. ntru_sha256 */
    void (*hash)(uint8_t[], uint16_t, uint8_t[]);

    /* hash function for 4 inputs, e.g. ntru_sha256_4way */
    void (*hash_4way)(uint8_t *[4], uint16_t, uint8_t *[4]);

    /* output length of the hash function */
    uint16_t hlen;

    /* number of bits of the public key to hash */
    uint16_t pklen;
} NtruEncParams;

/*
 * An IEEE 1361.1 parameter set that gives 112 bits of security and is optimized for key size.
 */
extern const NtruEncParams EES401EP1;

/*
 * An IEEE 1361.1 parameter set that gives 128 bits of security and is optimized for key size.
 */
extern const NtruEncParams EES449EP1;

/*
 * An IEEE 1361.1 parameter set that gives 192 bits of security and is optimized for key size.
 */
extern const NtruEncParams EES677EP1;

/*
 * An IEEE 1361.1 parameter set that gives 256 bits of security and is optimized for key size.
 */
extern const NtruEncParams EES1087EP2;

/*
 * An IEEE 1361.1 parameter set that gives 112 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
extern const NtruEncParams EES541EP1;

/*
 * An IEEE 1361.1 parameter set that gives 128 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
extern const NtruEncParams EES613EP1;

/*
 * An IEEE 1361.1 parameter set that gives 192 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
extern const NtruEncParams EES887EP1;

/*
 * An IEEE 1361.1 parameter set that gives 256 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
extern const NtruEncParams EES1171EP1;

/*
 * An IEEE 1361.1 parameter set that gives 112 bits of security and is
 * optimized for encryption/decryption speed.
 */
extern const NtruEncParams EES659EP1;

/*
 * An IEEE 1361.1 parameter set that gives 128 bits of security and is
 * optimized for encryption/decryption speed.
 */
extern const NtruEncParams EES761EP1;

/*
 * An IEEE 1361.1 parameter set that gives 192 bits of security and is
 * optimized for encryption/decryption speed.
 */
extern const NtruEncParams EES1087EP1;

/*
 * An IEEE 1361.1 parameter set that gives 256 bits of security and is
 * optimized for encryption/decryption speed.
 */
extern const NtruEncParams EES1499EP1;

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
/*
 * A product-form parameter set that gives 112 bits of security.
 */
extern const NtruEncParams EES401EP2;

/*
 * A product-form parameter set that gives 128 bits of security.
 * DEPRECATED -- use EES443EP1 instead.
 */
extern const NtruEncParams EES439EP1;

/*
 * A product-form parameter set that gives 128 bits of security.
 */
extern const NtruEncParams EES443EP1;

/*
 * A product-form parameter set that gives 192 bits of security.
 * DEPRECATED -- use EES587EP1 instead.
 */
extern const NtruEncParams EES593EP1;

/*
 * A product-form parameter set that gives 192 bits of security.
 */
extern const NtruEncParams EES587EP1;

/*
 * A product-form parameter set that gives 256 bits of security.
 */
extern const NtruEncParams EES743EP1;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

#ifndef NTRU_AVOID_HAMMING_WT_PATENT

/*
 * The default parameter set for 112 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_112_BITS EES401EP2

/*
 * The default parameter set for 128 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_128_BITS EES443EP1

/*
 * The default parameter set for 192 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_192_BITS EES587EP1

/*
 * The default parameter set for 256 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_256_BITS EES743EP1

#define ALL_PARAM_SETS {EES401EP1, EES449EP1, EES677EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1, EES761EP1, EES1087EP1, EES1499EP1, EES401EP2, EES439EP1, EES443EP1, EES593EP1, EES587EP1, EES743EP1}

#else

/*
 * The default parameter set for 112 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_112_BITS EES401EP1

/*
 * The default parameter set for 128 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_128_BITS EES449EP1

/*
 * The default parameter set for 192 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_192_BITS EES677EP1

/*
 * The default parameter set for 256 bits of security.
 */
#define NTRU_DEFAULT_PARAMS_256_BITS EES1087EP2

#define ALL_PARAM_SETS {EES401EP1, EES449EP1, EES677EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1, EES761EP1, EES1087EP1, EES1499EP1}

#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

/**
 * @brief Ciphertext length
 *
 * Returns the length of an encrypted message in bytes for a given parameter set.
 *
 * @param params
 * @return the length in bytes or 0 if params->q is not a power of two
 */
uint16_t ntru_enc_len(const NtruEncParams *params);

/**
 * @brief Ciphertext length
 *
 * Returns the length of an encrypted message in bytes for a given N and q value.
 *
 * @param N
 * @param q
 * @return the length in bytes or 0 if q is not a power of two
 */
uint16_t ntru_enc_len_Nq(uint16_t N, uint16_t q);

#endif   /* NTRU_ENCPARAMS_H */
