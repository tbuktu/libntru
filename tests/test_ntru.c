#include "string.h"
#include "test_ntru.h"
#include "test_util.h"
#include "ntru.h"
#include "rand.h"

void encrypt_poly(NtruIntPoly *m, NtruTernPoly *r, NtruIntPoly *h, NtruIntPoly *e, int q) {
    ntru_mult_tern(h, r, e);
    ntru_add_int_mod(e, m, q);
}

void decrypt_poly(NtruIntPoly *e, NtruProdPoly *t, NtruIntPoly *c, int q) {
    ntru_mult_prod(e, t, c);
    ntru_mult_fac(c, 3);
    ntru_add_int(c, e);

    ntru_mod_center(c, q);
    ntru_mod_center(c, 3);
}

int test_keygen() {
    NtruEncParams params = APR2011_439_FAST;
    NtruEncKeyPair kp;
    int valid = ntru_gen_key_pair(&params, &kp, ntru_rand_default) == 0;

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
    char seed[17];
    strcpy(seed, "my test password");
    valid &= ntru_gen_key_pair_det(&params, &kp, ntru_rand_igf2, seed, strlen(seed)) == 0;
    char password2[17];
    strcpy(password2, "my test password");
    NtruEncKeyPair kp2;
    valid &= ntru_gen_key_pair_det(&params, &kp2, ntru_rand_igf2, password2, strlen(password2)) == 0;
    valid &= equals_key_pair(&kp, &kp2);

    print_result("test_keygen", valid);
    return valid;
}

int test_encr_decr_param(NtruEncParams *params) {
    NtruEncKeyPair kp;
    int valid = ntru_gen_key_pair(params, &kp, ntru_rand_default) == 0;

    /* test ntru_encrypt() */
    int enc_len = ntru_enc_len(params->N, params->q);
    char plain[19];
    strcpy(plain, "test message 12345");
    int plain_len = strlen(plain);
    char encrypted[enc_len];
    valid &= ntru_encrypt((char*)&plain, plain_len, &kp.pub, params, ntru_rand_default, (char*)&encrypted) == 0;
    char decrypted[plain_len];
    int dec_len;
    valid &= ntru_decrypt((char*)&encrypted, &kp, params, (unsigned char*)&decrypted, &dec_len) == 0;
    valid &= equals_arr((unsigned char*)&plain, (unsigned char*)&decrypted, plain_len);

    /* test ntru_encrypt_det() */
    char pub_arr[ntru_pub_len(params->N, params->q)];
    ntru_export_pub(&kp.pub, pub_arr);
    NtruEncPubKey pub2;
    ntru_import_pub(pub_arr, &pub2);
    valid = ntru_equals_int(&kp.pub.h, &pub2.h);
    char seed[11];
    strcpy(seed, "seed value");
    valid &= ntru_encrypt_det((char*)&plain, plain_len, &kp.pub, params, ntru_rand_igf2, seed, strlen(seed), (char*)&encrypted) == 0;
    char plain2[19];
    strcpy(plain2, "test message 12345");
    char seed2[11];
    strcpy(seed2, "seed value");
    char encrypted2[enc_len];
    valid &= ntru_encrypt_det((char*)&plain2, plain_len, &pub2, params, ntru_rand_igf2, seed2, strlen(seed2), (char*)&encrypted2) == 0;
    valid &= strncmp(encrypted, encrypted2, enc_len) == 0;
    return valid;
}

int test_encr_decr() {
    /* test one param set for which maxm1=0 and one for which maxm1>0 */
    NtruEncParams params743 = APR2011_743_FAST;
    NtruEncParams params1087 = EES1087EP2_FAST;
    int valid = test_encr_decr_param(&params743);
    valid &= test_encr_decr_param(&params1087);

    print_result("test_encr_decr", valid);
    return valid;
}

int test_ntru() {
    int valid = test_keygen();
    valid &= test_encr_decr();
    return valid;
}
