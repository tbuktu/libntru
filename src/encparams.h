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

    /*
     * whether to treat ternary polynomials as sparsely populated (1) or
     * densely (0)
     */
    uint8_t sparse;

    /* hash function, e.g. ntru_sha256 */
    void (*hash)(uint8_t[], uint16_t, uint8_t[]);

    /* output length of the hash function */
    uint16_t hlen;

    /* number of bits of the public key to hash */
    uint16_t pklen;
} NtruEncParams;

/*
 * An IEEE 1361.1 parameter set that gives 112 bits of security and is optimized for key size.
 */
#define EES401EP1 {\
    "EES401EP1",   /* name */\
    401,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    113,           /* df */\
    0,\
    0,\
    113,           /* dm0 */\
    112,           /* db */\
    11,            /* c */\
    32,            /* min_calls_r */\
    9,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 4},     /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    114            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 128 bits of security and is optimized for key size.
 */
#define EES449EP1 {\
    "EES449EP1",   /* name */\
    449,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    134,           /* df */\
    0,\
    0,\
    134,           /* dm0 */\
    128,           /* db */\
    9,             /* c */\
    31,            /* min_calls_r */\
    9,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 3},     /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    128            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 192 bits of security and is optimized for key size.
 */
#define EES677EP1 {\
    "EES677EP1",   /* name */\
    677,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    157,           /* df */\
    0,\
    0,\
    157,           /* dm0 */\
    192,           /* db */\
    11,            /* c */\
    27,            /* min_calls_r */\
    9,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 3},     /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    192            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 256 bits of security and is optimized for key size.
 */
#define EES1087EP2 {\
    "EES1087EP2",  /* name */\
    1087,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    120,           /* df */\
    0,\
    0,\
    120,           /* dm0 */\
    256,           /* db */\
    13,            /* c */\
    25,            /* min_calls_r */\
    14,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 3},     /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    256            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 112 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
#define EES541EP1 {\
    "EES541EP1",   /* name */\
    541,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    49,            /* df */\
    0,\
    0,\
    49,            /* dm0 */\
    112,           /* db */\
    12,            /* c */\
    15,            /* min_calls_r */\
    11,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 5},     /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    112            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 128 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
#define EES613EP1 {\
    "EES613EP1",   /* name */\
    613,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    55,            /* df */\
    0,\
    0,\
    55,            /* dm0 */\
    128,           /* db */\
    11,            /* c */\
    16,            /* min_calls_r */\
    13,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 4},     /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    128            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 192 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
#define EES887EP1 {\
    "EES887EP1",   /* name */\
    887,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    81,            /* df */\
    0,\
    0,\
    81,            /* dm0 */\
    192,           /* db */\
    10,            /* c */\
    13,            /* min_calls_r */\
    12,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 4},     /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    192            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 256 bits of security and is
 * a tradeoff between key size and encryption/decryption speed.
 */
#define EES1171EP1 {\
    "EES1171EP1",  /* name */\
    1171,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    106,           /* df */\
    0,\
    0,\
    106,           /* dm0 */\
    256,           /* db */\
    12,            /* c */\
    20,            /* min_calls_r */\
    15,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 4},     /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    256            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 112 bits of security and is
 * optimized for encryption/decryption speed.
 */
#define EES659EP1 {\
    "EES659EP1",   /* name */\
    659,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    38,            /* df */\
    0,\
    0,\
    38,            /* dm0 */\
    112,           /* db */\
    11,            /* c */\
    11,            /* min_calls_r */\
    14,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 6},     /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    112            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 128 bits of security and is
 * optimized for encryption/decryption speed.
 */
#define EES761EP1 {\
    "EES761EP1",   /* name */\
    761,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    42,            /* df */\
    0,\
    0,\
    42,            /* dm0 */\
    128,           /* db */\
    12,            /* c */\
    13,            /* min_calls_r */\
    16,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 5},     /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    128            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 192 bits of security and is
 * optimized for encryption/decryption speed.
 */
#define EES1087EP1 {\
    "EES1087EP1",  /* name */\
    1087,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    63,            /* df */\
    0,\
    0,\
    63,            /* dm0 */\
    192,           /* db */\
    13,            /* c */\
    13,            /* min_calls_r */\
    14,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 5},     /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    192            /* pklen */\
}

/*
 * An IEEE 1361.1 parameter set that gives 256 bits of security and is
 * optimized for encryption/decryption speed.
 */
#define EES1499EP1 {\
    "EES1499EP1",  /* name */\
    1499,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    79,            /* df */\
    0,\
    0,\
    79,            /* dm0 */\
    256,           /* db */\
    13,            /* c */\
    17,            /* min_calls_r */\
    19,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 5},     /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    256            /* pklen */\
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
/*
 * A product-form parameter set that gives 112 bits of security.
 */
#define EES401EP2 {\
    "EES401EP2",   /* name */\
    401,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    8,             /* df1 */\
    8,             /* df2 */\
    6,             /* df3 */\
    101,           /* dm0 */\
    112,           /* db */\
    11,            /* c */\
    10,            /* min_calls_r */\
    6,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 16},    /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    112            /* pklen */\
}

/*
 * A product-form parameter set that gives 128 bits of security.
 */
#define EES439EP1 {\
    "EES439EP1",   /* name */\
    439,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    9,             /* df1 */\
    8,             /* df2 */\
    5,             /* df3 */\
    112,           /* dm0 */\
    128,           /* db */\
    9,             /* c */\
    15,            /* min_calls_r */\
    6,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 16},    /* oid */\
    1,             /* sparse */\
    ntru_sha1,     /* hash */\
    20,            /* hlen */\
    128            /* pklen */\
}

/*
 * A product-form parameter set that gives 192 bits of security.
 */
#define EES593EP1 {\
    "EES593EP1",   /* name */\
    593,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    10,            /* df1 */\
    10,            /* df2 */\
    8,             /* df3 */\
    158,           /* dm0 */\
    192,           /* db */\
    11,            /* c */\
    12,            /* min_calls_r */\
    5,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 16},    /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    192            /* pklen */\
}

/*
 * A product-form parameter set that gives 256 bits of security.
 */
#define EES743EP1 {\
    "EES743EP1",   /* name */\
    743,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    11,            /* df1 */\
    11,            /* df2 */\
    15,            /* df3 */\
    204,           /* dm0 */\
    256,           /* db */\
    13,            /* c */\
    12,            /* min_calls_r */\
    7,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 16},    /* oid */\
    1,             /* sparse */\
    ntru_sha256,   /* hash */\
    32,            /* hlen */\
    256            /* pklen */\
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
#define ALL_PARAM_SETS {EES401EP1, EES449EP1, EES677EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1, EES761EP1, EES1087EP1, EES1499EP1, EES401EP2, EES439EP1, EES593EP1, EES743EP1}
#else
#define ALL_PARAM_SETS {EES401EP1, EES449EP1, EES677EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1, EES761EP1, EES1087EP1, EES1499EP1}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint16_t ntru_enc_len(NtruEncParams *params);

uint16_t ntru_enc_len_Nq(uint16_t N, uint16_t q);

#endif   /* NTRU_ENCPARAMS_H */
