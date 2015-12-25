#include <string.h>
#include "test_ntru.h"
#include "test_util.h"
#include "ntru.h"
#include "poly.h"

void encrypt_poly(NtruIntPoly *m, NtruTernPoly *r, NtruIntPoly *h, NtruIntPoly *e, uint16_t q) {
    ntru_mult_tern(h, r, e, q);
    ntru_add_int(e, m);
    ntru_mod_mask(e, q-1);
}

void decrypt_poly(NtruIntPoly *e, NtruEncPrivKey *priv, NtruIntPoly *d, uint16_t modulus) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (priv->t.prod_flag)
        ntru_mult_prod(e, &priv->t.poly.prod, d, modulus-1);
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        ntru_mult_tern(e, &priv->t.poly.tern, d, modulus-1);
    ntru_mod_mask(d, modulus-1);
    ntru_mult_fac(d, 3);
    ntru_add_int(d, e);
    ntru_mod_center(d, modulus);
    ntru_mod3(d);
    uint16_t i;
    for (i=0; i<d->N; i++)
        if (d->coeffs[i] == 2)
            d->coeffs[i] = -1;
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
        decrypt_poly(&e, &kp.priv, &c, params.q);
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
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    uint8_t valid = ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;

    /* create a regular key pair (one private, one public) */
    NtruEncKeyPair kp;
    valid &= ntru_gen_key_pair(params, &kp, &rand_ctx) == NTRU_SUCCESS;

    /* randomly choose the number of public keys for testing ntru_gen_key_pair_multi and ntru_gen_pub */
    uint32_t num_pub_keys;
    valid &= ntru_rand_generate((uint8_t*)&num_pub_keys, sizeof(num_pub_keys), &rand_ctx) == NTRU_SUCCESS;
    num_pub_keys %= 10;
    num_pub_keys++;   /* 1 <= num_pub_keys <= 10 */

    /* create a key pair with multiple public keys (using ntru_gen_key_pair_multi) */
    NtruEncPrivKey priv_multi1;
    NtruEncPubKey pub_multi1[num_pub_keys];
    valid &= ntru_gen_key_pair_multi(params, &priv_multi1, pub_multi1, &rand_ctx, num_pub_keys) == NTRU_SUCCESS;
    /* create a key pair with multiple public keys (using ntru_gen_pub) */
    NtruEncKeyPair kp_multi2;
    NtruEncPubKey pub_multi2[num_pub_keys-1];
    valid &= ntru_gen_key_pair(params, &kp_multi2, &rand_ctx) == NTRU_SUCCESS;
    uint16_t i;
    for (i=0; i<num_pub_keys-1; i++)
      valid &= ntru_gen_pub(params, &kp_multi2.priv, &pub_multi2[i], &rand_ctx) == NTRU_SUCCESS;

    uint16_t max_len = ntru_max_msg_len(params);
    uint8_t plain[max_len];
    valid &= ntru_rand_generate(plain, max_len, &rand_ctx) == NTRU_SUCCESS;
    uint16_t enc_len = ntru_enc_len(params);
    uint8_t encrypted[enc_len];
    uint8_t decrypted[max_len];
    uint16_t plain_len;
    for (plain_len=0; plain_len<=max_len; plain_len++) {
        /* test single public key */
        valid &= ntru_encrypt((uint8_t*)&plain, plain_len, &kp.pub, params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;
        uint16_t dec_len;
        valid &= ntru_decrypt((uint8_t*)&encrypted, &kp, params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
        valid &= equals_arr((uint8_t*)&plain, (uint8_t*)&decrypted, plain_len);

        /* test multiple public keys */
        uint8_t i;
        for (i=0; i<num_pub_keys; i++) {
            uint8_t rand_value;
            valid &= ntru_rand_generate(&rand_value, 1, &rand_ctx) == NTRU_SUCCESS;
            if (rand_value%100 != 0)   /* only test 1 out of 100 */
                continue;

            /* test priv_multi1/pub_multi1  */
            valid &= ntru_encrypt((uint8_t*)&plain, plain_len, &pub_multi1[i], params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;
            NtruEncKeyPair kp_decrypt1 = {priv_multi1, pub_multi1[i]};
            uint16_t dec_len;
            valid &= ntru_decrypt((uint8_t*)&encrypted, &kp_decrypt1, params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
            valid &= equals_arr((uint8_t*)&plain, (uint8_t*)&decrypted, plain_len);

            /* test kp_multi2 + pub_multi2 */
            NtruEncPubKey *pub = i==0 ? &kp_multi2.pub : &pub_multi2[i-1];
            valid &= ntru_encrypt((uint8_t*)&plain, plain_len, pub, params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;
            NtruEncKeyPair kp_decrypt2 = {kp_multi2.priv, *pub};
            valid &= ntru_decrypt((uint8_t*)&encrypted, &kp_decrypt2, params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
            valid &= equals_arr((uint8_t*)&plain, (uint8_t*)&decrypted, plain_len);
        }
    }

    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
    return valid;
}

/* tests ntru_encrypt() with a deterministic RNG */
uint8_t test_encr_decr_det(NtruEncParams *params, uint8_t *digest_expected) {
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
    NtruRandGen rng_plaintext = NTRU_RNG_IGF2;
    char plain_seed_char[25];
    strcpy(plain_seed_char, "seed value for plaintext");
    uint8_t plain_seed[25];
    str_to_uint8(plain_seed_char, plain_seed);
    valid &= ntru_rand_init_det(&rand_ctx_plaintext, &rng_plaintext, plain_seed, strlen(plain_seed_char)) == NTRU_SUCCESS;
    valid &= ntru_rand_generate(plain, max_len, &rand_ctx_plaintext) == NTRU_SUCCESS;
    valid &= ntru_rand_release(&rand_ctx_plaintext) == NTRU_SUCCESS;
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
    valid &= ntru_rand_init_det(&rand_ctx, &rng, seed, strlen(seed_char)) == NTRU_SUCCESS;
    NtruRandContext rand_ctx2;
    NtruRandGen rng2 = NTRU_RNG_IGF2;
    valid &= ntru_rand_init_det(&rand_ctx2, &rng2, seed2, strlen(seed2_char)) == NTRU_SUCCESS;

    uint8_t decrypted[max_len];
    uint16_t plain_len;
    uint16_t dec_len;
    for (plain_len=0; plain_len<=max_len; plain_len++) {
        valid &= ntru_encrypt((uint8_t*)&plain, plain_len, &kp.pub, params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;
        valid &= ntru_encrypt((uint8_t*)&plain2, plain_len, &pub2, params, &rand_ctx2, (uint8_t*)&encrypted2) == NTRU_SUCCESS;
        valid &= memcmp(encrypted, encrypted2, enc_len) == 0;

        valid &= ntru_decrypt((uint8_t*)&encrypted, &kp, params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
        valid &= equals_arr((uint8_t*)&plain, (uint8_t*)&decrypted, plain_len);
    }

    uint8_t digest[20];
    ntru_sha1(encrypted, enc_len, digest);
    valid &= memcmp(digest, digest_expected, 20) == 0;

    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
    valid &= ntru_rand_release(&rand_ctx2) == NTRU_SUCCESS;

    return valid;
}

uint8_t test_encr_decr() {
    NtruEncParams param_arr[] = ALL_PARAM_SETS;
    uint8_t valid = 1;
    uint8_t i;

    /* SHA-1 digests of deterministic ciphertexts */
    uint8_t digests_expected[][20] = {
        {0xf8, 0x39, 0xbf, 0xb6, 0xa4, 0x99, 0x50, 0xde, 0xd0, 0x9f,   /* EES401EP1 */
         0xce, 0x55, 0xac, 0x23, 0xf1, 0x8e, 0x11, 0x0f, 0x76, 0x3d},
        {0x01, 0x6a, 0xbe, 0xae, 0x79, 0xdd, 0xf7, 0x9c, 0x90, 0x70,   /* EES449EP1 */
         0x02, 0x2e, 0x7e, 0x70, 0x05, 0xc4, 0xcb, 0x87, 0x8c, 0x60},
        {0xff, 0x5a, 0xfb, 0x06, 0xe0, 0xbe, 0xf9, 0x96, 0x7b, 0x2f,   /* EES677EP1 */
         0x6c, 0xde, 0x43, 0x8f, 0x2f, 0x48, 0xf3, 0x2b, 0x90, 0x8b},
        {0xc1, 0xbe, 0x9a, 0x9b, 0x85, 0xba, 0xa4, 0x0a, 0xc9, 0x45,   /* EES1087EP2 */
         0xa4, 0x92, 0xdf, 0xd3, 0x34, 0x03, 0x6b, 0x1b, 0x77, 0x29},
        {0xdb, 0xa4, 0x6f, 0xb2, 0xb1, 0xf0, 0x8d, 0xb1, 0xe3, 0x07,   /* EES541EP1 */
         0xf9, 0xb4, 0x4b, 0x96, 0x9e, 0xa9, 0x83, 0x56, 0x77, 0x69},
        {0x0c, 0x70, 0xf6, 0x40, 0x96, 0xfa, 0xaf, 0x26, 0xb4, 0xc0,   /* EES613EP1 */
         0x2d, 0xcd, 0xe4, 0x16, 0xc0, 0x56, 0xda, 0xbd, 0xbd, 0x6f},
        {0xb0, 0x39, 0xe6, 0xa3, 0xb7, 0x08, 0x60, 0x90, 0x5e, 0x39,   /* EES887EP1 */
         0xdb, 0xac, 0x9b, 0xba, 0xa2, 0xb8, 0xd9, 0x68, 0x91, 0x5a},
        {0x3d, 0x98, 0x20, 0xc1, 0xcf, 0xdf, 0x59, 0x77, 0x5a, 0x4a,   /* EES1171EP1 */
         0x1a, 0x1a, 0xb7, 0xed, 0xa0, 0x4b, 0x6c, 0xfa, 0x67, 0x72},
        {0x5d, 0x45, 0x53, 0xed, 0xb8, 0xce, 0xff, 0x84, 0x4f, 0x09,   /* EES659EP1 */
         0x49, 0x82, 0x5c, 0x06, 0x35, 0x2a, 0xc9, 0x71, 0xfa, 0x17},
        {0x85, 0xb9, 0xbe, 0x9b, 0x89, 0x64, 0x24, 0x06, 0x6b, 0x38,   /* EES761EP1 */
         0x76, 0x7c, 0x7e, 0x2a, 0xc6, 0x12, 0x48, 0x7a, 0x36, 0x62},
        {0x07, 0x6f, 0x5f, 0x62, 0x7f, 0x81, 0xdb, 0xd8, 0x0d, 0x26,   /* EES1087EP1 */
         0x2e, 0x1a, 0x64, 0x8c, 0x68, 0x02, 0xb3, 0xaf, 0x18, 0xa7},
        {0xf3, 0x16, 0xdf, 0x16, 0xe9, 0xa3, 0x4c, 0x40, 0x30, 0xff,   /* EES1499EP1 */
         0x5d, 0x66, 0xd8, 0x53, 0x2b, 0x07, 0x8a, 0x17, 0x48, 0xb4},
        {0x7f, 0xbb, 0x91, 0x11, 0xea, 0x2e, 0x59, 0x5d, 0x25, 0x42,   /* EES401EP2 */
         0xea, 0x07, 0x88, 0x05, 0x1a, 0xab, 0x37, 0xda, 0x9b, 0x33},
        {0x55, 0x76, 0x32, 0x9f, 0x18, 0x0a, 0xbb, 0x14, 0x63, 0xd9,   /* EES439EP1 */
         0x23, 0xc3, 0x5d, 0xd0, 0x8e, 0x17, 0xa5, 0xa2, 0x61, 0x75},
        {0x5e, 0xe5, 0x6c, 0x47, 0xde, 0x6e, 0x2f, 0x9c, 0x5f, 0x47,   /* EES443EP1 */
         0x7, 0x46, 0xe9, 0x1f, 0x90, 0xb3, 0x47, 0x7d, 0x40, 0x38},
        {0xb9, 0x40, 0x15, 0xbe, 0x43, 0xb9, 0x0f, 0xb3, 0x27, 0xfe,   /* EES593EP1 */
         0x41, 0x8a, 0x44, 0x76, 0x9e, 0xfe, 0xbe, 0xe5, 0x82, 0xae},
        {0xbd, 0xa1, 0xf5, 0x07, 0x48, 0x9e, 0x49, 0x94, 0xca, 0x18,   /* EES587EP1 */
         0x3e, 0x4d, 0xa5, 0xf7, 0xee, 0x8a, 0x23, 0x67, 0x62, 0xf9},
        {0xbd, 0xd9, 0x2a, 0x79, 0x89, 0x07, 0x9f, 0x64, 0xf9, 0x35,   /* EES743EP1 */
         0xb6, 0x90, 0x4f, 0xd3, 0xfa, 0x70, 0xc9, 0xf9, 0x30, 0xb0}
    };

    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        valid &= test_encr_decr_nondet(&param_arr[i]);
        valid &= test_encr_decr_det(&param_arr[i], digests_expected[i]);
    }

    print_result("test_encr_decr", valid);
    return valid;
}

uint8_t test_ntru() {
    uint8_t valid = test_keygen();
    valid &= test_encr_decr();
    return valid;
}
