#include <stdio.h>
#include "poly.h"

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

int rand_int(int N, int pow2q, NtruIntPoly *poly, int (*rng)(unsigned[], int)) {
    unsigned rand_data[N];
    if (!rng(rand_data, N))
        return 0;

    poly->N = N;
    int shift = 8 * sizeof rand_data[0] - pow2q;
    while (--N >= 0)
        poly->coeffs[N] = rand_data[N] >> shift;

    return 1;
}

void print_result(char *test_name, int valid) {
    printf("  %-17s%s\n", test_name, valid?"✓":"FAIL");
}
