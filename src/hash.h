#ifndef NTRU_HASH_H
#define NTRU_HASH_H

#include <stdint.h>

void ntru_sha1(uint8_t *input, uint16_t input_len, uint8_t *digest);

void ntru_sha1_4way(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

void ntru_sha256(uint8_t *input, uint16_t input_len, uint8_t *digest);

void ntru_sha256_4way(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

#endif   /* NTRU_HASH_H */
