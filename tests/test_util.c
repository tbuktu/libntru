#include <stdio.h>
#include "test_util.h"

int equals_int(NtruIntPoly *a, NtruIntPoly *b) {
    if (a->N != b->N)
        return 0;

    int i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i] != b->coeffs[i])
            return 0;

    return 1;
}

int equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, int modulus) {
    if (a->N != b->N)
        return 0;

    int i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i]%modulus != b->coeffs[i]%modulus)
            return 0;

    return 1;
}

int equals_tern(NtruTernPoly *a, NtruTernPoly *b) {
    if (a->N != b->N)
        return 0;
    if (a->num_ones != b->num_ones)
        return 0;
    if (a->num_neg_ones != b->num_neg_ones)
        return 0;

    int i;
    for (i=0; i<a->num_ones; i++)
        if (a->ones[i] != b->ones[i])
            return 0;
    for (i=0; i<a->num_neg_ones; i++)
        if (a->neg_ones[i] != b->neg_ones[i])
            return 0;

    return 1;
}

int equals_prod(NtruProdPoly *a, NtruProdPoly *b) {
    return a->N==b->N && equals_tern(&a->f1, &b->f1) && equals_tern(&a->f2, &b->f2) && equals_tern(&a->f3, &b->f3);
}

int equals_key_pair(NtruEncKeyPair *kp1, NtruEncKeyPair *kp2) {
    if (kp1->priv.q != kp2->priv.q)
        return 0;
    if (!equals_prod(&kp1->priv.t, &kp2->priv.t))
        return 0;
    if (kp1->pub.q != kp2->pub.q)
        return 0;
    if (!equals_int(&kp1->pub.h, &kp2->pub.h))
        return 0;
    return 1;
}

int equals_arr(unsigned char *arr1, unsigned char *arr2, int len) {
    int i;
    for (i=0; i<len; i++)
        if (arr1[i] != arr2[i])
            return 0;

    return 1;
}

int rand_int(int N, int pow2q, NtruIntPoly *poly, int (*rng)(unsigned[], int, NtruRandContext*), NtruRandContext *rand_ctx) {
    unsigned rand_data[N];
    if (!rng(rand_data, N, rand_ctx))
        return 0;

    poly->N = N;
    int shift = 8 * sizeof rand_data[0] - pow2q;
    while (--N >= 0)
        poly->coeffs[N] = rand_data[N] >> shift;

    return 1;
}

void print_result(char *test_name, int valid) {
#ifdef WIN32
    printf("  %-17s%s\n", test_name, valid?"OK":"FAIL");
#else
    printf("  %-17s%s\n", test_name, valid?"✓":"FAIL");
#endif
}
