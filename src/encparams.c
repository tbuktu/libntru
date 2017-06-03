#include "encparams.h"
#include "arith.h"

const NtruPrimeParams NTRUPRIME_739 = {\
    "NTRUPRM_739",   /* name */\
    739,             /* p */\
    9829,            /* q */\
    204,             /* t */\
    6553             /* inv_3 */
};

const NtruEncParams EES401EP1 = {\
    "EES401EP1",   /* name */\
    401,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    113,           /* df */\
    0,\
    0,\
    133,           /* dg */\
    113,           /* dm0 */\
    112,           /* db */\
    11,            /* c */\
    32,            /* min_calls_r */\
    9,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 4},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    114            /* pklen */\
};

const NtruEncParams EES449EP1 = {\
    "EES449EP1",   /* name */\
    449,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    134,           /* df */\
    0,\
    0,\
    149,           /* dg */\
    134,           /* dm0 */\
    128,           /* db */\
    9,             /* c */\
    31,            /* min_calls_r */\
    9,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 3},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    128            /* pklen */\
};

const NtruEncParams EES677EP1 = {\
    "EES677EP1",   /* name */\
    677,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    157,           /* df */\
    0,\
    0,\
    225,           /* dg */\
    157,           /* dm0 */\
    192,           /* db */\
    11,            /* c */\
    27,            /* min_calls_r */\
    9,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 3},     /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    192            /* pklen */\
};

const NtruEncParams EES1087EP2 = {\
    "EES1087EP2",  /* name */\
    1087,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    120,           /* df */\
    0,\
    0,\
    362,           /* dg */\
    120,           /* dm0 */\
    256,           /* db */\
    13,            /* c */\
    25,            /* min_calls_r */\
    14,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 3},     /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    256            /* pklen */\
};

const NtruEncParams EES541EP1 = {\
    "EES541EP1",   /* name */\
    541,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    49,            /* df */\
    0,\
    0,\
    180,           /* dg */\
    49,            /* dm0 */\
    112,           /* db */\
    12,            /* c */\
    15,            /* min_calls_r */\
    11,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 5},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    112            /* pklen */\
};

const NtruEncParams EES613EP1 = {\
    "EES613EP1",   /* name */\
    613,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    55,            /* df */\
    0,\
    0,\
    204,           /* dg */\
    55,            /* dm0 */\
    128,           /* db */\
    11,            /* c */\
    16,            /* min_calls_r */\
    13,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 4},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    128            /* pklen */\
};

const NtruEncParams EES887EP1 = {\
    "EES887EP1",   /* name */\
    887,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    81,            /* df */\
    0,\
    0,\
    295,           /* dg */\
    81,            /* dm0 */\
    192,           /* db */\
    10,            /* c */\
    13,            /* min_calls_r */\
    12,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 4},     /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    192            /* pklen */\
};

const NtruEncParams EES1171EP1 = {\
    "EES1171EP1",  /* name */\
    1171,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    106,           /* df */\
    0,\
    0,\
    390,           /* dg */\
    106,           /* dm0 */\
    256,           /* db */\
    12,            /* c */\
    20,            /* min_calls_r */\
    15,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 4},     /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    256            /* pklen */\
};

const NtruEncParams EES659EP1 = {\
    "EES659EP1",   /* name */\
    659,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    38,            /* df */\
    0,\
    0,\
    219,           /* dg */\
    38,            /* dm0 */\
    112,           /* db */\
    11,            /* c */\
    11,            /* min_calls_r */\
    14,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 6},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    112            /* pklen */\
};

const NtruEncParams EES761EP1 = {\
    "EES761EP1",   /* name */\
    761,           /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    42,            /* df */\
    0,\
    0,\
    253,           /* dg */\
    42,            /* dm0 */\
    128,           /* db */\
    12,            /* c */\
    13,            /* min_calls_r */\
    16,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 5},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    128            /* pklen */\
};

const NtruEncParams EES1087EP1 = {\
    "EES1087EP1",  /* name */\
    1087,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    63,            /* df */\
    0,\
    0,\
    362,           /* dg */\
    63,            /* dm0 */\
    192,           /* db */\
    13,            /* c */\
    13,            /* min_calls_r */\
    14,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 5},     /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    192            /* pklen */\
};

const NtruEncParams EES1499EP1 = {\
    "EES1499EP1",  /* name */\
    1499,          /* N */\
    2048,          /* q */\
    0,             /* prod_flag */\
    79,            /* df */\
    0,\
    0,\
    499,           /* dg */\
    79,            /* dm0 */\
    256,           /* db */\
    13,            /* c */\
    17,            /* min_calls_r */\
    19,            /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 5},     /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    256            /* pklen */\
};

#ifndef NTRU_AVOID_HAMMING_WT_PATENT

const NtruEncParams EES401EP2 = {\
    "EES401EP2",   /* name */\
    401,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    8,             /* df1 */\
    8,             /* df2 */\
    6,             /* df3 */\
    133,           /* dg */\
    101,           /* dm0 */\
    112,           /* db */\
    11,            /* c */\
    10,            /* min_calls_r */\
    6,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 2, 16},    /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    112            /* pklen */\
};

const NtruEncParams EES439EP1 = {\
    "EES439EP1",   /* name */\
    439,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    9,             /* df1 */\
    8,             /* df2 */\
    5,             /* df3 */\
    146,           /* dg */\
    112,           /* dm0 */\
    128,           /* db */\
    9,             /* c */\
    15,            /* min_calls_r */\
    6,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 16},    /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    ntru_sha1_8way, /* hash_8way */\
    20,            /* hlen */\
    128            /* pklen */\
};

const NtruEncParams EES443EP1 = {\
    "EES443EP1",   /* name */\
    443,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    9,             /* df1 */\
    8,             /* df2 */\
    5,             /* df3 */\
    148,           /* dg */\
    115,           /* dm0 */\
    128,           /* db */\
    9,             /* c */\
    8,             /* min_calls_r */\
    5,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 3, 17},    /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    128            /* pklen */\
};

const NtruEncParams EES593EP1 = {\
    "EES593EP1",   /* name */\
    593,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    10,            /* df1 */\
    10,            /* df2 */\
    8,             /* df3 */\
    197,           /* dg */\
    158,           /* dm0 */\
    192,           /* db */\
    11,            /* c */\
    12,            /* min_calls_r */\
    5,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 16},    /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    192            /* pklen */\
};

const NtruEncParams EES587EP1 = {\
    "EES587EP1",   /* name */\
    587,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    10,            /* df1 */\
    10,            /* df2 */\
    8,             /* df3 */\
    196,           /* dg */\
    157,           /* dm0 */\
    192,           /* db */\
    11,            /* c */\
    13,            /* min_calls_r */\
    7,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 5, 17},    /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    192            /* pklen */\
};

const NtruEncParams EES743EP1 = {\
    "EES743EP1",   /* name */\
    743,           /* N */\
    2048,          /* q */\
    1,             /* prod_flag */\
    11,            /* df1 */\
    11,            /* df2 */\
    15,            /* df3 */\
    247,           /* dg */\
    204,           /* dm0 */\
    256,           /* db */\
    13,            /* c */\
    12,            /* min_calls_r */\
    7,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 6, 16},    /* oid */\
    ntru_sha256,   /* hash */\
    ntru_sha256_4way, /* hash_4way */\
    ntru_sha256_8way, /* hash_8way */\
    32,            /* hlen */\
    256            /* pklen */\
};
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint16_t ntru_enc_len(const NtruEncParams *params) {
    return ntru_enc_len_Nq(params->N, params->q);
}

uint16_t ntru_enc_len_Nq(uint16_t N, uint16_t q) {
    /* make sure q is a power of 2 */
    if (q & (q-1))
        return 0;

    uint16_t len_bits = N * ntru_log2(q);
    uint16_t len_bytes = (len_bits+7) / 8;
    return len_bytes;
}
