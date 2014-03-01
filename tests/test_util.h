#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "ntru.h"
#include "poly.h"
#include "rand.h"

int equals_int(NtruIntPoly *a, NtruIntPoly *b);

int equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, int modulus);

int equals_key_pair(NtruEncKeyPair *kp1, NtruEncKeyPair *kp2);

int equals_arr(unsigned char *arr1, unsigned char *arr2, int len);

int rand_int(int N, int pow2q, NtruIntPoly *poly, int (*rng)(unsigned[], int, NtruRandContext*), NtruRandContext *rand_ctx);

void print_result(char *test_name, int valid);

#endif
