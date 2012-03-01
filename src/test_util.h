#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "poly.h"

int equals_int(NtruIntPoly *a, NtruIntPoly *b);

int equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, int modulus);

int equals_arr(unsigned char *arr1, unsigned char *arr2, int len);

int rand_int(int N, int pow2q, NtruIntPoly *poly, int (*rng)(unsigned[], int));

void print_result(char *test_name, int valid);

#endif
