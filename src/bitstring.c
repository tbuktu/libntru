#include <string.h>
#include "bitstring.h"

void ntru_append_byte(NtruBitStr *a, uint8_t b) {
    if (a->num_bytes == 0) {
        a->num_bytes = 1;
        a->buf[0] = b;
        a->last_byte_bits = 8;
    }
    else if (a->last_byte_bits == 8)
        a->buf[a->num_bytes++] = b;
    else {
        uint8_t s = 8 - a->last_byte_bits;
        a->buf[a->num_bytes-1] |= b << a->last_byte_bits;
        a->buf[a->num_bytes++] = b >> s;
    }
}

void ntru_append(NtruBitStr *a, uint8_t *b, uint16_t blen) {
    uint16_t i;
    for (i=0; i<blen; i++)
        ntru_append_byte(a, b[i]);
}

void ntru_trailing(NtruBitStr *a, uint8_t num_bits, NtruBitStr *b) {
    b->num_bytes = (num_bits+7) / 8;
    memcpy(&b->buf, &a->buf, sizeof b->buf);

    b->last_byte_bits = num_bits % 8;
    if (b->last_byte_bits == 0)
        b->last_byte_bits = 8;
    else {
        int8_t s = b->last_byte_bits;
        b->buf[b->num_bytes-1] = b->buf[b->num_bytes-1] & ((1<<s)-1);
    }
}

uint16_t ntru_leading(NtruBitStr *a, uint8_t num_bits) {
    uint16_t start_bit = (a->num_bytes-1)*8 + a->last_byte_bits - num_bits;
    uint16_t start_byte = start_bit / 8;
    uint8_t start_bit_in_byte = start_bit % 8;

    uint16_t sum = a->buf[start_byte] >> start_bit_in_byte;
    uint8_t shift = 8 - start_bit_in_byte;
    uint16_t i;
    for (i=start_byte+1; i<a->num_bytes-1; i++) {
        sum |= a->buf[i] << shift;
        shift += 8;
    }
    uint8_t final_bits = num_bits - shift;   /* #bits in the final byte */
    uint8_t afin = a->buf[a->num_bytes-1];
    sum |= (afin & ((1<<final_bits)-1)) << shift;

    return sum;
}

void ntru_truncate(NtruBitStr *a, uint8_t num_bits) {
    a->num_bytes -= num_bits / 8;
    a->last_byte_bits -= num_bits %= 8;
    if (a->last_byte_bits < 0) {
        a->last_byte_bits += 8;
        a->num_bytes--;
    }
}
