#include <stdio.h>
#include "test_util.h"
#include "bitstring.h"

uint8_t test_append() {
    uint8_t c[5] = {0};

    NtruBitStr b0 = {{0}, 0, 0};;
    c[0] = 78;
    ntru_append(&b0, (uint8_t*)&c, 1);
    uint8_t exp0[] = {78};
    uint8_t valid = equals_arr(b0.buf, exp0, 1);

    NtruBitStr b1 = {{0}, 0, 0};;
    c[1] = 251;
    ntru_append(&b1, (uint8_t*)&c, 2);
    uint8_t exp1[] = {78, 251};
    valid &= equals_arr(b1.buf, exp1, 2);

    NtruBitStr b2 = {{0}, 0, 0};;
    c[2] = 127;
    ntru_append(&b2, (uint8_t*)&c, 3);
    uint8_t exp2[] = {78, 251, 127};
    valid &= equals_arr(b2.buf, exp2, 3);

    NtruBitStr b3 = {{0}, 0, 0};;
    c[3] = 0;
    ntru_append(&b3, (uint8_t*)&c, 4);
    uint8_t exp3[] = {78, 251, 127, 0};
    valid &= equals_arr(b3.buf, exp3, 4);

    NtruBitStr b4 = {{0}, 0, 0};;
    c[4] = 100;
    ntru_append(&b4, (uint8_t*)&c, 5);
    uint8_t exp4[] = {78, 251, 127, 0, 100};
    valid &= equals_arr(b4.buf, exp4, 5);

    return valid;
}

uint8_t test_trailing() {
    NtruBitStr b0 = {{0}, 0, 0};
    uint8_t c0[] = {78};
    ntru_append(&b0, (uint8_t*)&c0, 1);
    NtruBitStr b0_trail;
    ntru_trailing(&b0, 3, &b0_trail);
    uint8_t exp0[] = {6};
    uint8_t valid = equals_arr(b0_trail.buf, exp0, 1);

    NtruBitStr b1 = {{0}, 0, 0};
    uint8_t c1[] = {78, 251};
    ntru_append(&b1, (uint8_t*)&c1, 2);
    NtruBitStr b1_trail;
    ntru_trailing(&b1, 9, &b1_trail);
    uint8_t exp1[] = {78, 1};
    valid &= equals_arr(b1_trail.buf, exp1, 2);

    uint8_t c2[] = {100};
    ntru_append(&b1_trail, (uint8_t*)&c2, 1);
    uint8_t exp2[] = {78, 201};
    valid &= equals_arr((uint8_t*)&b1_trail.buf, (uint8_t*)&exp2, 2);
    NtruBitStr b2_trail;
    ntru_trailing(&b1_trail, 13, &b2_trail);
    uint8_t exp3[] = {78, 9};
    valid &= equals_arr(b2_trail.buf, exp3, 2);
    ntru_trailing(&b1_trail, 11, &b2_trail);
    uint8_t exp4[] = {78, 1};
    valid &= equals_arr(b2_trail.buf, exp4, 2);

    uint8_t c3[] = {100};
    ntru_append(&b2_trail, (uint8_t*)&c3, 1);
    uint8_t exp5[] = {78, 33, 3};
    valid &= equals_arr(b2_trail.buf, exp5, 3);
    ntru_trailing(&b2_trail, 16, &b1_trail);
    uint8_t exp6[] = {78, 33};
    valid &= equals_arr(b1_trail.buf, exp6, 2);

    return valid;
}

uint8_t test_leading() {
    uint8_t valid = 1;

    NtruBitStr b0 = {{0}, 0, 0};
    uint8_t c0[] = {78, 42};
    ntru_append(&b0, (uint8_t*)&c0, 2);
    valid &= ntru_leading(&b0, 3) == 1;
    valid &= ntru_leading(&b0, 9) == 84;
    valid &= ntru_leading(&b0, 11) == 338;

    NtruBitStr b1;
    ntru_trailing(&b0, 11, &b1);
    uint8_t exp0[] = {78, 2};
    valid &= equals_arr(b1.buf, exp0, 2);
    valid &= ntru_leading(&b1, 11) == 590;
    valid &= ntru_leading(&b1, 5) == 9;

    uint8_t c1[] = {115};
    ntru_append(&b1, (uint8_t*)&c1, 1);
    valid &= ntru_leading(&b1, 9) == 230;
    valid &= ntru_leading(&b1, 11) == 922;

    uint8_t c2[] = {220};
    ntru_append(&b1, (uint8_t*)&c2, 1);
    valid &= ntru_leading(&b1, 6) == 55;

    return valid;
}

uint8_t test_bitstring() {
    uint8_t valid = test_append();
    valid &= test_trailing();
    valid &= test_leading();
    print_result("test_bitstring", valid);

    return valid;
}
