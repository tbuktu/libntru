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

void print_result(char *test_name, int valid) {
    printf("  %s\t%s\n", test_name, valid?"✓":"FAIL");
}
