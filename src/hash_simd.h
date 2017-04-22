#ifndef NTRU_HASH_SIMD_H
#define NTRU_HASH_SIMD_H

#include <stdint.h>

void ntru_sha1_4way_simd(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

void ntru_sha1_8way_simd(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]);

void ntru_sha256_4way_simd(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

void ntru_sha256_8way_simd(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]);

#endif   /* NTRU_HASH_SIMD_H */
