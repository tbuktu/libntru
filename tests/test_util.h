#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdint.h>
#include "ntru.h"
#include "poly.h"
#include "rand.h"

uint8_t equals_int(NtruIntPoly *a, NtruIntPoly *b);

uint8_t equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus);

uint8_t equals_key_pair(NtruEncKeyPair *kp1, NtruEncKeyPair *kp2);

uint8_t equals_arr(uint8_t *arr1, uint8_t *arr2, uint16_t len);

uint8_t rand_int(uint16_t N, uint16_t pow2q, NtruIntPoly *poly, uint8_t (*rng)(unsigned[], uint16_t, NtruRandContext*), NtruRandContext *rand_ctx);

void print_result(char *test_name, uint8_t valid);

#endif
