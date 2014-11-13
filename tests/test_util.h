#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdint.h>
#include "ntru.h"
#include "poly.h"
#include "rand.h"

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
#define ALL_PARAM_SETS {EES401EP1, EES449EP1, EES667EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1, EES761EP1, EES1087EP1, EES1499EP1, EES401EP2, EES439EP1, EES593EP1, EES743EP1}
#else
#define ALL_PARAM_SETS {EES401EP1, EES449EP1, EES667EP1, EES1087EP2, EES541EP1, EES613EP1, EES887EP1, EES1171EP1, EES659EP1, EES761EP1, EES1087EP1, EES1499EP1}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint8_t equals_int(NtruIntPoly *a, NtruIntPoly *b);

uint8_t equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus);

uint8_t equals_key_pair(NtruEncKeyPair *kp1, NtruEncKeyPair *kp2);

uint8_t equals_arr(uint8_t *arr1, uint8_t *arr2, uint16_t len);

uint8_t rand_int(uint16_t N, uint16_t pow2q, NtruIntPoly *poly, NtruRandContext *rand_ctx);

/**
 * @brief string to uint8_t array
 *
 * Converts a char array to a uint8_t array. If char is longer than uint8_t,
 * only the least significant 8 bits of each element are copied.
 *
 * @param in the NtruEncrypt parameters to use
 * @param out pointer to write the key pair to (output parameter)
 */
void str_to_uint8(char *in, uint8_t *out);

void print_result(char *test_name, uint8_t valid);

#endif
