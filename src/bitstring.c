#include <string.h>
#include "bitstring.h"

void ntru_append_char(NtruBitStr *a, unsigned char b) {
    if (a->num_bytes == 0) {
        a->num_bytes = 1;
        a->buf[0] = b;
        a->last_byte_bits = 8;
    }
    else if (a->last_byte_bits == 8)
        a->buf[a->num_bytes++] = b;
    else {
        int s = 8 - a->last_byte_bits;
        a->buf[a->num_bytes-1] |= b << a->last_byte_bits;
        a->buf[a->num_bytes++] = b >> s;
    }
}

void ntru_append(NtruBitStr *a, unsigned char *b, int blen) {
    int i;
    for (i=0; i<blen; i++)
        ntru_append_char(a, b[i]);
}

void ntru_trailing(NtruBitStr *a, int num_bits, NtruBitStr *b) {
    b->num_bytes = (num_bits+7) / 8;
    memcpy(&b->buf, &a->buf, sizeof b->buf);

    b->last_byte_bits = num_bits % 8;
    if (b->last_byte_bits == 0)
        b->last_byte_bits = 8;
    else {
        int s = b->last_byte_bits;
        b->buf[b->num_bytes-1] = b->buf[b->num_bytes-1] & ((1<<s)-1);
    }
}

int ntru_leading(NtruBitStr *a, int num_bits) {
    int start_bit = (a->num_bytes-1)*8 + a->last_byte_bits - num_bits;
    int start_byte = start_bit / 8;

    int start_bit_in_byte = start_bit % 8;
    int sum = a->buf[start_byte] >> start_bit_in_byte;
    int shift = 8 - start_bit_in_byte;
    int i;
    for (i=start_byte+1; i<a->num_bytes; i++) {
        sum |= a->buf[i] << shift;
        shift += 8;
    }

    return sum;
}

void ntru_truncate(NtruBitStr *a, int num_bits) {
    a->num_bytes -= num_bits / 8;
    a->last_byte_bits -= num_bits %= 8;
    if (a->last_byte_bits < 0) {
        a->last_byte_bits += 8;
        a->num_bytes--;
    }
}
