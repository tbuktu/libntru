#ifndef NTRU_BITSTRING_H
#define NTRU_BITSTRING_H

#include <stdint.h>
#include "encparams.h"

typedef struct NtruBitStr {
    uint8_t buf[NTRU_MAX_BIT_STR_LEN];
    uint16_t num_bytes;   /* includes the last byte even if only some of its bits are used */
    int8_t last_byte_bits;   /* last_byte_bits <= 8 */
} NtruBitStr;

void ntru_append(NtruBitStr *a, uint8_t *b, uint16_t blen);

void ntru_trailing(NtruBitStr *a, uint8_t num_bits, NtruBitStr *b);

uint16_t ntru_leading(NtruBitStr *a, uint8_t num_bits);

void ntru_truncate(NtruBitStr *a, uint8_t num_bits);

#endif   /* NTRU_BITSTRING_H */
