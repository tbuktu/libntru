#include <stdio.h>
#include <string.h>
#include "test_util.h"

uint8_t equals_int(NtruIntPoly *a, NtruIntPoly *b) {
    if (a->N != b->N)
        return 0;

    uint16_t i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i] != b->coeffs[i])
            return 0;

    return 1;
}

uint8_t equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus) {
    if (a->N != b->N)
        return 0;

    uint16_t i;
    for (i=0; i<a->N; i++)
        if ((a->coeffs[i]-b->coeffs[i]) % modulus)
            return 0;

    return 1;
}

uint8_t equals_tern(NtruTernPoly *a, NtruTernPoly *b) {
    if (a->N != b->N)
        return 0;
    if (a->num_ones != b->num_ones)
        return 0;
    if (a->num_neg_ones != b->num_neg_ones)
        return 0;

    uint16_t i;
    for (i=0; i<a->num_ones; i++)
        if (a->ones[i] != b->ones[i])
            return 0;
    for (i=0; i<a->num_neg_ones; i++)
        if (a->neg_ones[i] != b->neg_ones[i])
            return 0;

    return 1;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
uint8_t equals_prod(NtruProdPoly *a, NtruProdPoly *b) {
    return a->N==b->N && equals_tern(&a->f1, &b->f1) && equals_tern(&a->f2, &b->f2) && equals_tern(&a->f3, &b->f3);
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint8_t equals_key_pair(NtruEncKeyPair *kp1, NtruEncKeyPair *kp2) {
    if (kp1->priv.q != kp2->priv.q)
        return 0;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (kp1->priv.t.prod_flag && !equals_prod(&kp1->priv.t.poly.prod, &kp2->priv.t.poly.prod))
        return 0;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    if (!kp1->priv.t.prod_flag && !equals_tern(&kp1->priv.t.poly.tern, &kp2->priv.t.poly.tern))
        return 0;
    if (kp1->pub.q != kp2->pub.q)
        return 0;
    if (!equals_int(&kp1->pub.h, &kp2->pub.h))
        return 0;
    return 1;
}

uint8_t equals_arr(uint8_t *arr1, uint8_t *arr2, uint16_t len) {
    uint16_t i;
    for (i=0; i<len; i++)
        if (arr1[i] != arr2[i])
            return 0;

    return 1;
}

uint8_t rand_int(uint16_t N, uint16_t pow2q, NtruIntPoly *poly, NtruRandContext *rand_ctx) {
    uint16_t rand_data[N];
    if (!rand_ctx->rand_gen->generate((uint8_t*)rand_data, N*2, rand_ctx))
        return 0;

    poly->N = N;
    uint16_t shift = 16 - pow2q;
    while ((int16_t)--N >= 0)
        poly->coeffs[N] = rand_data[N] >> shift;

    return 1;
}

void str_to_uint8(char *in, uint8_t *out) {
    size_t len = strlen(in);
    size_t i;
    for (i=0; i<len; i++)
        out[i] = (uint8_t)in[i];
}

void print_result(char *test_name, uint8_t valid) {
#ifdef WIN32
    printf("  %-17s%s\n", test_name, valid?"OK":"FAIL");
#else
    printf("  %-17s%s\n", test_name, valid?"✓":"FAIL");
#endif
}
