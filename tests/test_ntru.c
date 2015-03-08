#include "string.h"
#include "test_ntru.h"
#include "test_util.h"
#include "ntru.h"
#include "rand.h"
#include "encparams.h"

void encrypt_poly(NtruIntPoly *m, NtruTernPoly *r, NtruIntPoly *h, NtruIntPoly *e, uint16_t q) {
    ntru_mult_tern(h, r, e, q);
    ntru_add_int_mod(e, m, q);
}

void decrypt_poly(NtruIntPoly *e, NtruEncPrivKey *priv, uint16_t q, NtruIntPoly *d, uint16_t modulus) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (priv->t.prod_flag)
        ntru_mult_prod(e, &priv->t.poly.prod, d, modulus);
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        ntru_mult_tern(e, &priv->t.poly.tern, d, modulus);
    ntru_mod(d, q);
    ntru_mult_fac(d, 3);
    ntru_add_int(d, e);
    ntru_mod_center(d, q);
    ntru_mod3(d);
}

uint8_t gen_key_pair(char *seed, NtruEncParams *params, NtruEncKeyPair *kp) {
    uint16_t seed_len = strlen(seed);
    uint8_t seed_uint8[seed_len];
    str_to_uint8(seed, seed_uint8);
    NtruRandContext rand_ctx;
    NtruRandGen rng = NTRU_RNG_IGF2;
    ntru_rand_init_det(&rand_ctx, &rng, seed_uint8, seed_len);
    rand_ctx.seed = seed_uint8;
    rand_ctx.seed_len = seed_len;
    uint8_t result = 1;
    result &= ntru_gen_key_pair(params, kp, &rand_ctx);
    result &= ntru_rand_release(&rand_ctx);
    return result;
}

uint8_t test_keygen() {
    NtruEncParams param_arr[] = ALL_PARAM_SETS;
    uint8_t valid = 1;

    uint8_t i;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        NtruEncParams params = param_arr[i];
        NtruEncKeyPair kp;
        NtruRandContext rand_ctx;
        ntru_rand_init(&rand_ctx, &rng);
        valid &= ntru_gen_key_pair(&params, &kp, &rand_ctx) == NTRU_SUCCESS;

        /* encrypt a random message */
        NtruTernPoly m;
        ntru_rand_tern(params.N, params.N/3, params.N/3, &m, &rand_ctx);
        NtruIntPoly m_int;
        ntru_tern_to_int(&m, &m_int);

        NtruTernPoly r;
        ntru_rand_tern(params.N, params.N/3, params.N/3, &r, &rand_ctx);
        ntru_rand_release(&rand_ctx);
        NtruIntPoly e;
        encrypt_poly(&m_int, &r, &kp.pub.h, &e, params.q);

        /* decrypt and verify */
        NtruIntPoly c;
        decrypt_poly(&e, &kp.priv, params.q, &c, params.q);
        valid &= ntru_equals_int(&m_int, &c);

        /* test deterministic key generation */
        valid &= gen_key_pair("my test password", &params, &kp) == NTRU_SUCCESS;
        char seed2_char[19];
        strcpy(seed2_char, "my test password");
        uint8_t seed2[strlen(seed2_char)];
        str_to_uint8(seed2_char, seed2);
        NtruEncKeyPair kp2;
        NtruRandGen rng = NTRU_RNG_IGF2;
        NtruRandContext rand_ctx2;
        ntru_rand_init_det(&rand_ctx2, &rng, seed2, strlen(seed2_char));
        valid &= ntru_gen_key_pair(&params, &kp2, &rand_ctx2) == NTRU_SUCCESS;
        ntru_rand_release(&rand_ctx2);
        valid &= equals_key_pair(&kp, &kp2);
    }

    print_result("test_keygen", valid);
    return valid;
}

/* tests ntru_encrypt() with a non-deterministic RNG */
uint8_t test_encr_decr_nondet(NtruEncParams *params) {
    NtruEncKeyPair kp;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    ntru_rand_init(&rand_ctx, &rng);
    uint8_t valid = ntru_gen_key_pair(params, &kp, &rand_ctx) == NTRU_SUCCESS;

    uint16_t max_len = ntru_max_msg_len(params);
    uint8_t plain[max_len];
    ntru_rand_generate(plain, max_len, &rand_ctx);
    uint16_t enc_len = ntru_enc_len(params);
    uint8_t encrypted[enc_len];
    uint8_t decrypted[max_len];
    uint16_t plain_len;
    for (plain_len=0; plain_len<=max_len; plain_len++) {
        valid &= ntru_encrypt((uint8_t*)&plain, plain_len, &kp.pub, params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;
        uint16_t dec_len;
        valid &= ntru_decrypt((uint8_t*)&encrypted, &kp, params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
        valid &= equals_arr((uint8_t*)&plain, (uint8_t*)&decrypted, plain_len);
    }

    ntru_rand_release(&rand_ctx);
    return valid;
}

/* tests ntru_encrypt() with a deterministic RNG */
uint8_t test_encr_decr_det(NtruEncParams *params) {
    NtruEncKeyPair kp;
    uint8_t valid = gen_key_pair("seed value for key generation", params, &kp) == NTRU_SUCCESS;
    uint8_t pub_arr[ntru_pub_len(params)];
    ntru_export_pub(&kp.pub, pub_arr);
    NtruEncPubKey pub2;
    ntru_import_pub(pub_arr, &pub2);
    valid &= ntru_equals_int(&kp.pub.h, &pub2.h);

    NtruRandContext rand_ctx_plaintext;
    uint16_t max_len = ntru_max_msg_len(params);
    uint8_t plain[max_len];
    NtruRandGen rng_plaintext = NTRU_RNG_DEFAULT;
    ntru_rand_init(&rand_ctx_plaintext, &rng_plaintext);
    ntru_rand_generate(plain, max_len, &rand_ctx_plaintext);
    ntru_rand_release(&rand_ctx_plaintext);
    uint8_t plain2[max_len];
    memcpy(plain2, plain, max_len);
    uint16_t enc_len = ntru_enc_len(params);
    uint8_t encrypted[enc_len];
    uint8_t encrypted2[enc_len];

    char seed_char[11];
    strcpy(seed_char, "seed value");
    uint8_t seed[11];
    str_to_uint8(seed_char, seed);
    char seed2_char[11];
    strcpy(seed2_char, "seed value");
    uint8_t seed2[11];
    str_to_uint8(seed2_char, seed2);

    NtruRandContext rand_ctx;
    NtruRandGen rng = NTRU_RNG_IGF2;
    ntru_rand_init_det(&rand_ctx, &rng, seed, strlen(seed_char));
    NtruRandContext rand_ctx2;
    NtruRandGen rng2 = NTRU_RNG_IGF2;
    ntru_rand_init_det(&rand_ctx2, &rng2, seed2, strlen(seed2_char));

    uint16_t plain_len;
    for (plain_len=0; plain_len<=max_len; plain_len++) {
        valid &= ntru_encrypt((uint8_t*)&plain, plain_len, &kp.pub, params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;

        valid &= ntru_encrypt((uint8_t*)&plain2, plain_len, &pub2, params, &rand_ctx2, (uint8_t*)&encrypted2) == NTRU_SUCCESS;

        valid &= memcmp(encrypted, encrypted2, enc_len) == 0;
    }

    ntru_rand_release(&rand_ctx);
    ntru_rand_release(&rand_ctx2);

    return valid;
}

uint8_t test_encr_decr() {
    NtruEncParams param_arr[] = ALL_PARAM_SETS;
    uint8_t valid = 1;
    uint8_t i;
    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        valid &= test_encr_decr_nondet(&param_arr[i]);
        valid &= test_encr_decr_det(&param_arr[i]);
    }

    print_result("test_encr_decr", valid);
    return valid;
}

uint8_t test_ntru() {
    uint8_t valid = test_keygen();
    valid &= test_encr_decr();
    return valid;
}
