#include <string.h>
#ifdef WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "test_ntru.h"
#include "test_util.h"
#include "ntru.h"
#include "poly.h"

void encrypt_poly(NtruIntPoly *m, NtruTernPoly *r, NtruIntPoly *h, NtruIntPoly *e, uint16_t q) {
    ntru_mult_tern(h, r, e, q);
    ntru_add(e, m);
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
    ntru_add(d, e);
    ntru_mod_center(d, modulus);
    ntru_mod3(d);
    uint16_t i;
    for (i=0; i<d->N; i++)
        if (d->coeffs[i] == 2)
            d->coeffs[i] = -1;
}

/** Returns 0 on error, 1 on success */
uint8_t gen_key_pair(char *seed, NtruEncParams *params, NtruEncKeyPair *kp) {
    uint16_t seed_len = strlen(seed);
    uint8_t seed_uint8[seed_len];
    str_to_uint8(seed, seed_uint8);
    NtruRandContext rand_ctx;
    NtruRandGen rng = NTRU_RNG_CTR_DRBG;
    ntru_rand_init_det(&rand_ctx, &rng, seed_uint8, seed_len);
    uint8_t result = 1;
    result &= ntru_gen_key_pair(params, kp, &rand_ctx) == NTRU_SUCCESS;
    result &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
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
        valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
        NtruIntPoly e;
        encrypt_poly(&m_int, &r, &kp.pub.h, &e, params.q);

        /* decrypt and verify */
        NtruIntPoly c;
        decrypt_poly(&e, &kp.priv, &c, params.q);
        valid &= ntru_equals_int(&m_int, &c);

        /* test deterministic key generation */
        valid &= gen_key_pair("my test password", &params, &kp);
        char seed2_char[19];
        strcpy(seed2_char, "my test password");
        uint8_t seed2[strlen(seed2_char)];
        str_to_uint8(seed2_char, seed2);
        NtruEncKeyPair kp2;
        NtruRandGen rng = NTRU_RNG_CTR_DRBG;
        NtruRandContext rand_ctx2;
        ntru_rand_init_det(&rand_ctx2, &rng, seed2, strlen(seed2_char));
        valid &= ntru_gen_key_pair(&params, &kp2, &rand_ctx2) == NTRU_SUCCESS;
        valid &= ntru_rand_release(&rand_ctx2) == NTRU_SUCCESS;
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
    uint8_t valid = gen_key_pair("seed value for key generation", params, &kp);
    uint8_t pub_arr[ntru_pub_len(params)];
    ntru_export_pub(&kp.pub, pub_arr);
    NtruEncPubKey pub2;
    ntru_import_pub(pub_arr, &pub2);
    valid &= ntru_equals_int(&kp.pub.h, &pub2.h);

    NtruRandContext rand_ctx_plaintext;
    uint16_t max_len = ntru_max_msg_len(params);
    uint8_t plain[max_len];
    NtruRandGen rng_plaintext = NTRU_RNG_CTR_DRBG;
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
    NtruRandGen rng = NTRU_RNG_CTR_DRBG;
    valid &= ntru_rand_init_det(&rand_ctx, &rng, seed, strlen(seed_char)) == NTRU_SUCCESS;
    NtruRandContext rand_ctx2;
    NtruRandGen rng2 = NTRU_RNG_CTR_DRBG;
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

    /*
     * SHA-1 digests of deterministic ciphertexts,
     * one set for big-endian environments and one for little-endian ones.
     * If/when the CTR_DRBG implementation is made endian independent,
     * only one set of digests will be needed here.
     */
    uint8_t digests_expected_little_endian[][20] = {
        {0xdf, 0xad, 0xcd, 0x25, 0x01, 0x9f, 0x3d, 0xb1, 0x06, 0x5f,   /* EES401EP1 */
         0x15, 0xbe, 0x8f, 0x69, 0xfd, 0x23, 0x88, 0x88, 0x2a, 0xc8},
        {0xc3, 0x8b, 0x8d, 0xdc, 0xfd, 0xef, 0xf8, 0x1b, 0xa6, 0x57,   /* EES449EP1 */
         0xeb, 0x66, 0x49, 0xe8, 0xe9, 0x4d, 0x70, 0xab, 0xce, 0x02},
        {0xfd, 0xa8, 0xb1, 0xdb, 0x96, 0xc4, 0x3a, 0xeb, 0x0c, 0x07,   /* EES677EP1 */
         0xef, 0xf7, 0xc0, 0xf4, 0x73, 0x59, 0x6e, 0xd9, 0x97, 0xb7},
        {0xe7, 0x53, 0xd6, 0x89, 0xc6, 0x06, 0x3d, 0xf1, 0x12, 0xf1,   /* EES1087EP2 */
         0xeb, 0x8b, 0xd8, 0x7c, 0x26, 0x67, 0xc9, 0xe5, 0x4a, 0x0e},
        {0x7a, 0x5d, 0x41, 0x88, 0x70, 0xef, 0x4f, 0xf3, 0xdf, 0xb9,   /* EES541EP1 */
         0xa8, 0x76, 0x00, 0x00, 0x6d, 0x65, 0x61, 0xe0, 0xce, 0x44},
        {0x69, 0x7b, 0x0a, 0x4f, 0xd6, 0x41, 0x04, 0x3f, 0x91, 0xe9,   /* EES613EP1 */
         0xb0, 0xa9, 0x42, 0xfe, 0x66, 0x4e, 0xcc, 0x4e, 0xbb, 0xd7},
        {0xac, 0x3a, 0x51, 0xd6, 0xaf, 0x6c, 0x38, 0xa8, 0x67, 0xde,   /* EES887EP1 */
         0xc8, 0xfe, 0xf7, 0xaf, 0x4a, 0x28, 0x6e, 0x30, 0xad, 0x98},
        {0x5f, 0x34, 0x5f, 0xf7, 0x32, 0x13, 0x06, 0x55, 0x6b, 0xb7,   /* EES1171EP1 */
         0x02, 0x7d, 0xb3, 0x16, 0xef, 0x84, 0x09, 0xe9, 0xa0, 0xff},
        {0x2e, 0x35, 0xd4, 0xa6, 0x99, 0xb8, 0x5e, 0x06, 0x47, 0x61,   /* EES659EP1 */
         0x68, 0x20, 0x26, 0xb0, 0x17, 0xa9, 0xc6, 0x37, 0xb7, 0x8e},
        {0x15, 0xde, 0x51, 0xbb, 0xc0, 0xe0, 0x39, 0xf2, 0xb6, 0x0e,   /* EES761EP1 */
         0x98, 0xa7, 0xae, 0x10, 0xbf, 0xfd, 0x02, 0xcc, 0x76, 0x43},
        {0x29, 0xac, 0x2d, 0x21, 0x29, 0x79, 0x98, 0x89, 0x1c, 0xa0,   /* EES1087EP1 */
         0x6c, 0xed, 0x7d, 0x68, 0x29, 0x9b, 0xb4, 0x9f, 0xe4, 0xd0},
        {0x2f, 0xf9, 0x32, 0x25, 0xbc, 0xd5, 0xad, 0xc4, 0x4b, 0x19,   /* EES1499EP1 */
         0xca, 0xe6, 0x52, 0x89, 0x2e, 0x29, 0x38, 0x5a, 0x61, 0xd7},
        {0xaf, 0x39, 0x02, 0xd5, 0xaa, 0xab, 0x29, 0xaa, 0x01, 0x99,   /* EES401EP2 */
         0xd1, 0xf4, 0x0f, 0x02, 0x35, 0x58, 0x71, 0x58, 0xdb, 0xdb},
        {0xa3, 0xd6, 0x5f, 0x7d, 0x5d, 0x66, 0x49, 0x1e, 0x15, 0xbc,   /* EES439EP1 */
         0xba, 0xf0, 0xfa, 0x07, 0x9d, 0xd3, 0x33, 0xf5, 0x9f, 0x37},
        {0xac, 0xea, 0xa3, 0xc8, 0x05, 0x8b, 0x23, 0x68, 0xaa, 0x9a,   /* EES443EP1 */
         0x3c, 0x9b, 0xdb, 0x7f, 0xbe, 0x7b, 0x49, 0x03, 0x94, 0xc8},
        {0x49, 0xfb, 0x90, 0x33, 0xaf, 0x12, 0xc7, 0x29, 0x17, 0x47,   /* EES593EP1 */
         0xf2, 0x09, 0xb9, 0xc3, 0x5d, 0xf4, 0x21, 0x5a, 0xbf, 0x98},
        {0x69, 0xa8, 0x36, 0x3d, 0xe1, 0xec, 0x9e, 0x89, 0xa1, 0x0a,   /* EES587EP1 */
         0xa5, 0xb7, 0x35, 0xbe, 0x5b, 0x75, 0xb6, 0xd8, 0xe1, 0x9a},
        {0x93, 0xfe, 0x81, 0xd5, 0x79, 0x2e, 0x34, 0xd8, 0xe3, 0x1f,   /* EES743EP1 */
         0xe5, 0x03, 0xb9, 0x06, 0xdc, 0x4f, 0x28, 0xb9, 0xaf, 0x37}
    };
    uint8_t digests_expected_big_endian[][20] = {
        {0xba, 0xeb, 0xb3, 0x0a, 0x1c, 0xcb, 0x90, 0x46, 0x50, 0x52,   /* EES401EP1 */
         0x20, 0x9d, 0xeb, 0x90, 0x21, 0xbc, 0xe9, 0x19, 0xcf, 0x25},
        {0x92, 0x38, 0x0d, 0xa0, 0x6b, 0xef, 0x0c, 0x98, 0x99, 0x13,   /* EES449EP1 */
         0x3a, 0xb7, 0xba, 0x84, 0xdc, 0xce, 0xea, 0xc4, 0x1e, 0x91},
        {0xaf, 0x10, 0xe4, 0x52, 0x51, 0xfb, 0x89, 0xf6, 0x1b, 0xae,   /* EES677EP1 */
         0xe0, 0x93, 0x72, 0x99, 0x4f, 0x4d, 0xc8, 0xb2, 0x15, 0xbe},
        {0x65, 0x38, 0xbf, 0x44, 0xa1, 0xdc, 0xf8, 0x46, 0x25, 0x19,   /* EES1087EP2 */
         0x1f, 0xe5, 0x99, 0x67, 0x0d, 0x08, 0x3c, 0x63, 0x41, 0x59},
        {0x06, 0x76, 0xd2, 0xa3, 0xed, 0xea, 0x00, 0x1f, 0x17, 0xfd,   /* EES541EP1 */
         0x6e, 0x7e, 0x05, 0xf3, 0xef, 0x30, 0x4e, 0x44, 0x42, 0x5a},
        {0x7b, 0x76, 0x8c, 0xf5, 0x97, 0xea, 0x07, 0x4e, 0xea, 0x91,   /* EES613EP1 */
         0xeb, 0xa4, 0xf1, 0x0e, 0xec, 0x30, 0x7a, 0x7e, 0xae, 0x32},
        {0x44, 0xa0, 0x03, 0x19, 0x44, 0x6b, 0x61, 0x5c, 0x97, 0xc0,   /* EES887EP1 */
         0x19, 0xec, 0xf6, 0x5e, 0x13, 0x28, 0x11, 0xda, 0xc2, 0xcc},
        {0x2f, 0x7e, 0xd4, 0x20, 0xe5, 0x84, 0x03, 0xfa, 0xa3, 0xbd,   /* EES1171EP1 */
         0xd0, 0x64, 0xb7, 0xbe, 0x36, 0x9d, 0xc8, 0x9d, 0x05, 0x0f},
        {0x2c, 0x52, 0x35, 0x93, 0x11, 0xbf, 0x88, 0x5d, 0xc8, 0xce,   /* EES659EP1 */
         0xe8, 0x7a, 0x3c, 0xb8, 0x23, 0x08, 0x73, 0xbf, 0xb2, 0xcb},
        {0xe0, 0x48, 0xa2, 0xcc, 0x52, 0x78, 0x53, 0x54, 0xf4, 0xfd,   /* EES761EP1 */
         0x0e, 0xb9, 0x23, 0x97, 0x7f, 0x9c, 0xa8, 0x13, 0x32, 0xe1},
        {0x33, 0x95, 0x90, 0x70, 0xee, 0x95, 0x7e, 0xcf, 0x1d, 0xc7,   /* EES1087EP1 */
         0x6e, 0x33, 0xa7, 0xf6, 0x07, 0xff, 0x92, 0xa2, 0x9d, 0xdc},
        {0x2f, 0x5e, 0x7c, 0x7b, 0xb7, 0x23, 0x13, 0x4d, 0x9e, 0xb5,   /* EES1499EP1 */
         0x82, 0x52, 0xd6, 0x57, 0xee, 0xc7, 0x44, 0x31, 0x4c, 0x8e},
        {0x00, 0xb5, 0xbe, 0x7e, 0xa3, 0x9b, 0xd4, 0xf8, 0x12, 0xf5,   /* EES401EP2 */
         0xa6, 0x7d, 0x44, 0xa4, 0x89, 0xf4, 0xbf, 0xb7, 0x91, 0x43},
        {0x77, 0x70, 0xef, 0x2c, 0x70, 0x8b, 0x40, 0xf5, 0x15, 0xba,   /* EES439EP1 */
         0xf4, 0x03, 0xef, 0xaa, 0x18, 0xbe, 0x04, 0x11, 0xd4, 0x59},
        {0x46, 0x96, 0xa9, 0x58, 0xae, 0xe6, 0x14, 0x75, 0x0c, 0x22,   /* EES443EP1 */
         0x78, 0x02, 0x5f, 0xe4, 0x6b, 0x94, 0xd4, 0x33, 0x75, 0x64},
        {0xf3, 0x1c, 0x73, 0x9b, 0x84, 0x8b, 0xda, 0x76, 0xb6, 0xcc,   /* EES593EP1 */
         0xf1, 0xf9, 0x4b, 0xc4, 0x85, 0x5f, 0xec, 0xf7, 0x86, 0x4a},
        {0xb1, 0xa3, 0x11, 0xdc, 0x48, 0x40, 0xc1, 0x9f, 0x3e, 0x56,   /* EES587EP1 */
         0x60, 0x8e, 0xcf, 0xd5, 0x76, 0xa7, 0x7c, 0x78, 0x84, 0x39},
        {0x35, 0xe1, 0x67, 0x89, 0x9d, 0x44, 0x26, 0x91, 0xaf, 0xc3,   /* EES743EP1 */
         0x69, 0x41, 0x82, 0xeb, 0x3b, 0x8c, 0xc4, 0xfd, 0xe5, 0x08}
    };
    uint8_t big_endian = htons(1) == 1;

    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        valid &= test_encr_decr_nondet(&param_arr[i]);
        valid &= test_encr_decr_det(&param_arr[i], big_endian?digests_expected_big_endian[i]:digests_expected_little_endian[i]);
    }

    print_result("test_encr_decr", valid);
    return valid;
}

uint8_t test_ntru() {
    uint8_t valid = test_keygen();
    valid &= test_encr_decr();
    return valid;
}
