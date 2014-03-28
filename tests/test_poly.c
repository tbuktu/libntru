#include <stdio.h>
#include "poly.h"
#include "ntru.h"
#include "rand.h"
#include "encparams.h"
#include "test_util.h"
#include "test_poly.h"

/**
 * @brief Multiplication of two general polynomials
 *
 * Multiplies a NtruIntPoly by another. The number of coefficients
 * must be the same for both polynomials.
 *
 * @param a a general polynomial
 * @param b a general polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_int(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    uint16_t i, k;
    for (k=0; k<N; k++) {
        int32_t ck = 0;
        for (i=0; i<N; i++)
            ck += b->coeffs[i] * a->coeffs[(N+k-i)%N];
        c->coeffs[k] = ck;
    }

    return 1;
}

/** tests ntru_mult_int_mod() */
uint8_t test_mult_int() {
    uint8_t valid = 1;

    /* multiplication modulo q */
    NtruIntPoly a1 = {11, {-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1}};
    NtruIntPoly b1 = {11, {14, 11, 26, 24, 14, 16, 30, 7, 25, 6, 19}};
    NtruIntPoly c1;
    ntru_mult_int_mod(&a1, &b1, &c1, 32);
    NtruIntPoly c1_exp = {11, {3, 25, -10, 21, 10, 7, 6, 7, 5, 29, -7}};
    valid &= ntru_equals_int(&c1_exp, &c1);

    /* ntru_mult_mod should give the same result as ntru_mult_int followed by ntru_mod */
    NtruIntPoly a3 = {11, {1, 0, -1, 1, 0, 1, 1, 1, -1, 1, -1}};
    NtruIntPoly b3 = {11, {0, 1, 1, 0, 0, -1, -1, 1, 1, -1, 1}};
    NtruIntPoly c3, c3_exp;
    ntru_mult_int_mod(&a3, &b3, &c3, 20);
    ntru_mult_int(&a3, &b3, &c3_exp);
    ntru_mod(&c3_exp, 20);
    valid &= equals_int_mod(&c3_exp, &c3, 20);

    print_result("test_mult_int", valid);
    return valid;
}

/* tests ntru_mult_tern() */
uint8_t test_mult_tern() {
    NtruTernPoly a;
    uint8_t valid = ntru_rand_tern(11, 3, 3, &a, ntru_rand_default, NULL);
    NtruIntPoly b;
    valid &= rand_int(11, 5, &b, ntru_rand_default, NULL);
    NtruIntPoly c_tern;
    ntru_mult_tern(&b, &a, &c_tern);
    NtruIntPoly a_int;
    ntru_tern_to_int(&a, &a_int);
    NtruIntPoly c_int;
    ntru_mult_int(&a_int, &b, &c_int);
    valid &= ntru_equals_int(&c_tern, &c_int);

    print_result("test_mult_tern", valid);
    return valid;
}

/* tests ntru_mult_prod() */
uint8_t test_mult_prod() {
    uint8_t valid = 1;
    uint16_t i;
    for (i=0; i<10; i++) {
        NtruProdPoly a;
        valid &= ntru_rand_prod(853, 8, 8, 8, 9, &a, ntru_rand_default, NULL);
        NtruIntPoly b;
        valid &= rand_int(853, 11, &b, ntru_rand_default, NULL);
        NtruIntPoly c_prod;
        ntru_mult_prod(&b, &a, &c_prod);
        NtruIntPoly a_int;
        ntru_prod_to_int(&a, &a_int);
        NtruIntPoly c_int;
        ntru_mult_int(&a_int, &b, &c_int);
        valid &= ntru_equals_int(&c_prod, &c_int);
    }

    print_result("test_mult_prod", valid);
    return valid;
}

uint8_t verify_inverse(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus) {
    NtruIntPoly c;
    ntru_mult_int_mod(a, b, &c, modulus);
    ntru_mod(&c, modulus);
    return ntru_equals1(&c);
}

/* tests ntru_invert() */
uint8_t test_inv() {
    uint8_t valid = 1;

    /* Verify an example from the NTRU tutorial */
    NtruIntPoly a1 = {11, {-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1}};
    NtruIntPoly b1;
    uint8_t invertible = ntru_invert(&a1, 32, &b1);
    NtruIntPoly b_exp = {11, {5, -23, 6, 16, 4, 15, 16, -10, -12, -14, -2}};
    valid &= invertible;
    valid &= ntru_equals_int(&b_exp, &b1);
    valid &= verify_inverse(&a1, &b1, 32);

    /* test 3 random polynomials */
    uint16_t num_invertible = 0;
    while (num_invertible < 3) {
        NtruIntPoly a_int;
        rand_int(853, 11, &a_int, ntru_rand_default, NULL);

        NtruIntPoly b;
        uint8_t invertible = ntru_invert(&a_int, 2048, &b);
        if (invertible) {
            valid &= verify_inverse(&a_int, &b, 2048);
            num_invertible++;
        }
    }

    /* test a non-invertible polynomial */
    NtruIntPoly a2 = {11, {-1, 0, 1, 1, 0, 0, -1, 0, -1, 0, 1}};
    NtruIntPoly b2;
    invertible = ntru_invert(&a2, 32, &b2);
    valid &= !invertible;

    print_result("test_inv", valid);
    return valid;
}

uint8_t test_arr() {
    NtruEncParams params = EES439EP1;
    uint8_t a[ntru_enc_len(&params)];
    NtruIntPoly p1;
    uint8_t valid = rand_int(params.N, 11, &p1, ntru_rand_default, NULL);
    ntru_to_arr(&p1, params.q, a);

    NtruIntPoly p2;
    ntru_from_arr(a, params.N, params.q, &p2);

    valid &= equals_int(&p1, &p2);
    print_result("test_arr", valid);
    return valid;
}

uint8_t test_poly() {
    uint8_t valid = 1;
    valid &= test_mult_int();
    valid &= test_mult_tern();
    valid &= test_mult_prod();
    valid &= test_inv();
    valid &= test_arr();
    return valid;
}
