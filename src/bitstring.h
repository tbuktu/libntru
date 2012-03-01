#ifndef BITSTRING_H
#define BITSTRING_H

#include "encparams.h"

typedef struct NtruBitStr {
    unsigned char buf[NTRU_MAX_BIT_STR_LEN];
    int num_bytes;   /* includes the last byte even if only some of its bits are used */
    int last_byte_bits;   /* last_byte_bits <= 8 */
} NtruBitStr;

void ntru_append(NtruBitStr *a, unsigned char *b, int blen);

void ntru_trailing(NtruBitStr *a, int num_bits, NtruBitStr *b);

int ntru_leading(NtruBitStr *a, int num_bits);

void ntru_truncate(NtruBitStr *a, int num_bits);

#endif   /* BITSTRING_H */
