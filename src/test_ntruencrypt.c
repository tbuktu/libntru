#include "test_ntruencrypt.h"
#include "test_util.h"
#include "ntruencrypt.h"

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
    struct NtruEncParams params = APR2011_439_FAST;
    NtruEncKeyPair kp;
    int valid = ntru_gen_key_pair(params, &kp, dev_urandom);

    /* encrypt a random message */
    NtruTernPoly m;
    ntru_rand_tern(params.N, params.N/3, params.N/3, &m, dev_urandom);
    NtruIntPoly m_int;
    ntru_tern_to_int(&m, &m_int);

    NtruTernPoly r;
    ntru_rand_tern(params.N, params.N/3, params.N/3, &r, dev_urandom);
    NtruIntPoly e;
    encrypt_poly(&m_int, &r, &kp.pub.h, &e, params.q);

    /* decrypt and verify */
    NtruIntPoly c;
    decrypt_poly(&e, &kp.priv.t, &c, params.q);
    valid &= equals_int(&m_int, &c);

    print_result("test_keygen", valid);
    return valid;
}

int test_ntruencrypt() {
    return test_keygen();
}
