#include "string.h"
#include "test_ntru.h"
#include "test_util.h"
#include "ntru.h"
#include "rand.h"

void encrypt_poly(NtruIntPoly *m, NtruTernPoly *r, NtruIntPoly *h, NtruIntPoly *e, uint16_t q) {
    ntru_mult_tern(h, r, e);
    ntru_add_int_mod(e, m, q);
}

void decrypt_poly(NtruIntPoly *e, NtruProdPoly *t, NtruIntPoly *c, uint16_t q) {
    ntru_mult_prod(e, t, c);
    ntru_mult_fac(c, 3);
    ntru_add_int(c, e);

    ntru_mod_center(c, q);
    ntru_mod_center(c, 3);
}

uint8_t test_keygen() {
    NtruEncParams params = APR2011_439_FAST;
    NtruEncKeyPair kp;
    uint8_t valid = ntru_gen_key_pair(&params, &kp, ntru_rand_default) == NTRU_SUCCESS;

    /* encrypt a random message */
    NtruTernPoly m;
    ntru_rand_tern(params.N, params.N/3, params.N/3, &m, ntru_rand_default, NULL);
    NtruIntPoly m_int;
    ntru_tern_to_int(&m, &m_int);

    NtruTernPoly r;
    ntru_rand_tern(params.N, params.N/3, params.N/3, &r, ntru_rand_default, NULL);
    NtruIntPoly e;
    encrypt_poly(&m_int, &r, &kp.pub.h, &e, params.q);

    /* decrypt and verify */
    NtruIntPoly c;
    decrypt_poly(&e, &kp.priv.t, &c, params.q);
    valid &= ntru_equals_int(&m_int, &c);

    /* test deterministic key generation */
    char seed_char[17];
    strcpy(seed_char, "my test password");
    uint8_t seed[strlen(seed_char)];
    uint16_t i;
    for (i=0; i<strlen(seed_char); i++)
        seed[i] = seed_char[i];
    valid &= ntru_gen_key_pair_det(&params, &kp, ntru_rand_igf2, seed, strlen(seed_char)) == NTRU_SUCCESS;
    char seed2_char[19];
    strcpy(seed2_char, "my test password");
    uint8_t seed2[strlen(seed2_char)];
    for (i=0; i<strlen(seed2_char); i++)
        seed2[i] = seed2_char[i];
    NtruEncKeyPair kp2;
    valid &= ntru_gen_key_pair_det(&params, &kp2, ntru_rand_igf2, seed2, strlen(seed2_char)) == NTRU_SUCCESS;
    valid &= equals_key_pair(&kp, &kp2);

    print_result("test_keygen", valid);
    return valid;
}

uint8_t test_encr_decr_param(NtruEncParams *params) {
    NtruEncKeyPair kp;
    uint8_t valid = ntru_gen_key_pair(params, &kp, ntru_rand_default) == NTRU_SUCCESS;

    /* test ntru_encrypt() */
    uint16_t enc_len = ntru_enc_len(params->N, params->q);
    char plain_char[19];
    strcpy(plain_char, "test message 12345");
    uint16_t i;
    size_t plain_len = strlen(plain_char);
    uint8_t plain[plain_len];
    for (i=0; i<plain_len; i++)
        plain[i] = plain_char[i];
    uint8_t encrypted[enc_len];
    valid &= ntru_encrypt((uint8_t*)&plain, plain_len, &kp.pub, params, ntru_rand_default, (uint8_t*)&encrypted) == NTRU_SUCCESS;
    uint8_t decrypted[plain_len];
    uint16_t dec_len;
    valid &= ntru_decrypt((uint8_t*)&encrypted, &kp, params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
    valid &= equals_arr((uint8_t*)&plain, (uint8_t*)&decrypted, plain_len);

    /* test ntru_encrypt_det() */
    uint8_t pub_arr[ntru_pub_len(params->N, params->q)];
    ntru_export_pub(&kp.pub, pub_arr);
    NtruEncPubKey pub2;
    ntru_import_pub(pub_arr, &pub2);
    valid = ntru_equals_int(&kp.pub.h, &pub2.h);
    char seed_char[11];
    strcpy(seed_char, "seed value");
    uint8_t seed[11];
    for (i=0; i<plain_len; i++)
        seed[i] = seed_char[i];
    valid &= ntru_encrypt_det((uint8_t*)&plain, plain_len, &kp.pub, params, ntru_rand_igf2, seed, strlen(seed_char), (uint8_t*)&encrypted) == NTRU_SUCCESS;
    char plain2_char[19];
    strcpy(plain2_char, "test message 12345");
    uint8_t plain2[plain_len];
    for (i=0; i<plain_len; i++)
        plain2[i] = plain2_char[i];
    char seed2_char[11];
    strcpy(seed2_char, "seed value");
    uint8_t seed2[11];
    for (i=0; i<strlen(seed2_char); i++)
        seed2[i] = seed2_char[i];
    uint8_t encrypted2[enc_len];
    valid &= ntru_encrypt_det((uint8_t*)&plain2, plain_len, &pub2, params, ntru_rand_igf2, seed2, strlen(seed2_char), (uint8_t*)&encrypted2) == NTRU_SUCCESS;
    valid &= strncmp((char*)encrypted, (char*)encrypted2, enc_len) == 0;
    return valid;
}

uint8_t test_encr_decr() {
    /* test one param set for which maxm1=0 and one for which maxm1>0 */
    NtruEncParams params743 = APR2011_743_FAST;
    NtruEncParams params1087 = EES1087EP2_FAST;
    uint8_t valid = test_encr_decr_param(&params743);
    valid &= test_encr_decr_param(&params1087);

    print_result("test_encr_decr", valid);
    return valid;
}

uint8_t test_ntru() {
    uint8_t valid = test_keygen();
    valid &= test_encr_decr();
    return valid;
}
