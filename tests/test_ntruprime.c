#include <string.h>
#include "test_ntruprime.h"
#include "poly.h"
#include "test_util.h"

uint8_t test_ntruprime_keygen() {
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    uint8_t valid = ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    NtruPrimeKeyPair kp;
    NtruPrimeParams params = NTRUPRIME_739;
    valid &= ntruprime_gen_key_pair(&params, &kp, &rand_ctx) == NTRU_SUCCESS;

    /* verify that h*f*3*g_inv==1 (mod q) */
    NtruIntPoly a;
    valid &= ntruprime_mult_poly(&kp.pub.h, &kp.priv.f, &a, params.q);
    ntruprime_mult_mod(&a, 3, params.q);
    NtruIntPoly b;
    valid &= ntruprime_mult_poly(&a, &kp.priv.g_inv, &b, params.q);
    valid &= equals_one(&b);

    print_result("test_ntruprime_keygen", valid);
    return valid;
}

uint8_t test_ntruprime() {
    uint8_t valid = test_ntruprime_keygen();
    return valid;
}
