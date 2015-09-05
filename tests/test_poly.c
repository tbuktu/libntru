#include <stdio.h>
#include <string.h>
#include "poly.h"
#include "ntru.h"
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
uint8_t ntru_mult_int_nomod(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c) {
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

/** tests ntru_mult_int() */
uint8_t test_mult_int() {
    uint8_t valid = 1;

    /* multiplication modulo q */
    NtruIntPoly a1 = {11, {-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1}};
    NtruIntPoly b1 = {11, {14, 11, 26, 24, 14, 16, 30, 7, 25, 6, 19}};
    NtruIntPoly c1;
    ntru_mult_int(&a1, &b1, &c1, 32-1);
    NtruIntPoly c1_exp = {11, {3, 25, -10, 21, 10, 7, 6, 7, 5, 29, -7}};
    valid &= equals_int_mod(&c1_exp, &c1, 32);

    /* ntru_mult_mod should give the same result as ntru_mult_int_nomod followed by ntru_mod_mask */
    NtruIntPoly a2 = {5, {1278, 1451, 850, 1071, 942}};
    NtruIntPoly b2 = {5, {571, 52, 1096, 1800, 662}};
    NtruIntPoly c2, c2_exp;
    valid &= ntru_mult_int(&a2, &b2, &c2, 2048-1);
    valid &= ntru_mult_int_nomod(&a2, &b2, &c2_exp);
    ntru_mod_mask(&c2_exp, 2048-1);
    valid &= equals_int_mod(&c2_exp, &c2, 2048);

    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    valid &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    int i;
    for (i=0; i<10; i++) {
        uint16_t N;
        valid &= rand_ctx.rand_gen->generate((uint8_t*)&N, sizeof N, &rand_ctx);
        N = 100 + (N%(NTRU_MAX_DEGREE-100));
        NtruIntPoly a3, b3, c3, c3_exp;
        valid &= rand_int(N, 11, &a3, &rand_ctx);
        valid &= rand_int(N, 11, &b3, &rand_ctx);
        valid &= ntru_mult_int_nomod(&a3, &b3, &c3_exp);
        ntru_mod_mask(&c3_exp, 2048-1);
        valid &= ntru_mult_int_16(&a3, &b3, &c3, 2048-1);
        valid &= equals_int_mod(&c3_exp, &c3, 2048);
#ifndef __ARMEL__
        valid &= ntru_mult_int_64(&a3, &b3, &c3, 2048-1);
        valid &= equals_int_mod(&c3_exp, &c3, 2048);
#endif
    }

    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
    print_result("test_mult_int", valid);
    return valid;
}

/* tests ntru_mult_tern() */
uint8_t test_mult_tern() {
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    uint8_t valid = ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;

    NtruTernPoly a;
    valid &= ntru_rand_tern(11, 3, 3, &a, &rand_ctx);
    NtruIntPoly b;
    valid &= rand_int(11, 5, &b, &rand_ctx);
    NtruIntPoly a_int;
    ntru_tern_to_int(&a, &a_int);
    NtruIntPoly c_int;
    ntru_mult_int(&a_int, &b, &c_int, 32-1);
    NtruIntPoly c_tern;
    ntru_mult_tern_32(&b, &a, &c_tern, 32-1);
    valid &= equals_int_mod(&c_tern, &c_int, 32);
#ifndef __ARMEL__
    ntru_mult_tern_64(&b, &a, &c_tern, 32-1);
    valid &= equals_int_mod(&c_tern, &c_int, 32);
#endif
#ifdef __SSSE3__
    ntru_mult_tern_sse(&b, &a, &c_tern, 32-1);
    valid &= equals_int_mod(&c_tern, &c_int, 32);
#endif

    int i;
    for (i=0; i<10; i++) {
        uint16_t N;
        valid &= rand_ctx.rand_gen->generate((uint8_t*)&N, sizeof N, &rand_ctx);
        N = 100 + (N%(NTRU_MAX_DEGREE-100));
        uint16_t num_ones;
        valid &= rand_ctx.rand_gen->generate((uint8_t*)&num_ones, sizeof num_ones, &rand_ctx);
        num_ones %= N/2;
        num_ones %= NTRU_MAX_ONES;
        uint16_t num_neg_ones;
        valid &= rand_ctx.rand_gen->generate((uint8_t*)&num_neg_ones, sizeof num_neg_ones, &rand_ctx);
        num_neg_ones %= N/2;
        num_neg_ones %= NTRU_MAX_ONES;
        valid &= ntru_rand_tern(N, num_ones, num_neg_ones, &a, &rand_ctx);
        valid &= rand_int(N, 11, &b, &rand_ctx);
        ntru_tern_to_int(&a, &a_int);
        ntru_mult_int_nomod(&a_int, &b, &c_int);
        ntru_mult_tern_32(&b, &a, &c_tern, 2048-1);
        valid &= equals_int_mod(&c_tern, &c_int, 2048);
#ifndef __ARMEL__
        ntru_mult_tern_64(&b, &a, &c_tern, 2048-1);
        valid &= equals_int_mod(&c_tern, &c_int, 2048);
#endif
#ifdef __SSSE3__
        ntru_mult_tern_sse(&b, &a, &c_tern, 2048-1);
        valid &= equals_int_mod(&c_tern, &c_int, 2048);
#endif
    }

    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

    print_result("test_mult_tern", valid);
    return valid;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
/* tests ntru_mult_prod() */
uint8_t test_mult_prod() {
    uint8_t valid = 1;
    uint16_t i;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    valid &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    uint16_t log_modulus = 11;
    uint16_t modulus = 1 << log_modulus;
    for (i=0; i<10; i++) {
        NtruProdPoly a;
        valid &= ntru_rand_prod(853, 8, 8, 8, 9, &a, &rand_ctx);
        NtruIntPoly b;
        valid &= rand_int(853, 1<<log_modulus, &b, &rand_ctx);
        NtruIntPoly c_prod;
        ntru_mult_prod(&b, &a, &c_prod, modulus-1);
        NtruIntPoly a_int;
        ntru_prod_to_int(&a, &a_int, modulus);
        NtruIntPoly c_int;
        ntru_mult_int(&a_int, &b, &c_int, modulus-1);
        valid &= equals_int_mod(&c_prod, &c_int, log_modulus);
    }
    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

    print_result("test_mult_prod", valid);
    return valid;
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint8_t verify_inverse(NtruPrivPoly *a, NtruIntPoly *b, uint16_t modulus) {
    NtruIntPoly c, a_int;

    ntru_priv_to_int(a, &a_int, modulus);
    ntru_mult_fac(&a_int, 3);
    a_int.coeffs[0] += 1;

    ntru_mult_int(&a_int, b, &c, modulus-1);
    ntru_mod_mask(&c, modulus-1);
    return ntru_equals1(&c);
}

/* tests ntru_invert() */
uint8_t test_inv() {
    uint8_t valid = 1;

    /* Verify a short polynomial */
    NtruPrivPoly a1 = {0, {{11, 4, 4, {1, 2, 6, 9}, {0, 3, 4, 10}}}};
    NtruIntPoly b1;
    uint8_t invertible = ntru_invert_32(&a1, 32-1, &b1);
    valid &= invertible;
    valid &= verify_inverse(&a1, &b1, 32);
    invertible &= ntru_invert_64(&a1, 32-1, &b1);
    valid &= invertible;
    valid &= verify_inverse(&a1, &b1, 32);

    /* test 3 random polynomials */
    uint16_t num_invertible = 0;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    valid &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    while (num_invertible < 3) {
        NtruPrivPoly a2;
        a2.prod_flag = 0;   /* ternary */
        valid &= ntru_rand_tern(853, 100, 100, &a2.poly.tern, &rand_ctx);

        NtruIntPoly b;
        uint8_t invertible = ntru_invert(&a2, 2048-1, &b);
        if (invertible) {
            valid &= verify_inverse(&a2, &b, 2048);
            num_invertible++;
        }
    }
#ifdef NTRU_AVOID_HAMMING_WT_PATENT
    num_invertible = 0;
    while (num_invertible < 3) {
        NtruPrivPoly a3;
        a3.prod_flag = 0;   /* ternary */
        valid &= ntru_rand_tern(853, 100, 100, &a3.poly.tern, &rand_ctx);

        NtruIntPoly b;
        uint8_t invertible = ntru_invert(&a3, 2048-1, &b);
        if (invertible) {
            valid &= verify_inverse(&a3, &b, 2048);
            num_invertible++;
        }
    }
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

    /* test a non-invertible polynomial */
    NtruPrivPoly a2 = {0, {{11, 2, 3, {3, 10}, {0, 6, 8}}}};
    NtruIntPoly b2;
    invertible = ntru_invert(&a2, 32-1, &b2);
    valid &= !invertible;

    print_result("test_inv", valid);
    return valid;
}

uint8_t test_arr() {
    NtruEncParams params = EES1087EP1;
    uint8_t a[ntru_enc_len(&params)];
    NtruIntPoly p1;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    uint8_t valid = ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    valid &= rand_int(params.N, 11, &p1, &rand_ctx);
    ntru_to_arr_32(&p1, params.q, a);
    valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;
    NtruIntPoly p2;
    ntru_from_arr(a, params.N, params.q, &p2);
    valid &= equals_int(&p1, &p2);

    uint8_t b[sizeof(a)];
    ntru_to_arr_64(&p1, params.q, b);
    valid &= memcmp(a, b, sizeof a) == 0;

#ifdef __SSSE3__
    ntru_to_arr_sse_2048(&p1, b);
    valid &= memcmp(a, b, sizeof a) == 0;
#endif

    print_result("test_arr", valid);
    return valid;
}

uint8_t test_poly() {
    uint8_t valid = 1;
    valid &= test_mult_int();
    valid &= test_mult_tern();
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    valid &= test_mult_prod();
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    valid &= test_inv();
    valid &= test_arr();
    return valid;
}
