#include "test_util.h"
#include "bitstring.h"

#include <stdio.h>

int test_append() {
    unsigned char c[5] = {0};

    NtruBitStr b0 = {{0}, 0, 0};;
    c[0] = 78;
    ntru_append(&b0, (unsigned char*)&c, 1);
    unsigned char exp0[] = {78};
    int valid = equals_arr(b0.buf, exp0, 1);

    NtruBitStr b1 = {{0}, 0, 0};;
    c[1] = 251;
    ntru_append(&b1, (unsigned char*)&c, 2);
    unsigned char exp1[] = {78, 251};
    valid &= equals_arr(b1.buf, exp1, 2);

    NtruBitStr b2 = {{0}, 0, 0};;
    c[2] = 127;
    ntru_append(&b2, (unsigned char*)&c, 3);
    unsigned char exp2[] = {78, 251, 127};
    valid &= equals_arr(b2.buf, exp2, 3);

    NtruBitStr b3 = {{0}, 0, 0};;
    c[3] = 0;
    ntru_append(&b3, (unsigned char*)&c, 4);
    unsigned char exp3[] = {78, 251, 127, 0};
    valid &= equals_arr(b3.buf, exp3, 4);

    NtruBitStr b4 = {{0}, 0, 0};;
    c[4] = 100;
    ntru_append(&b4, (unsigned char*)&c, 5);
    unsigned char exp4[] = {78, 251, 127, 0, 100};
    valid &= equals_arr(b4.buf, exp4, 5);

    print_result("test_append", valid);
    return valid;
}

int test_trailing() {
    NtruBitStr b0 = {{0}, 0, 0};
    unsigned char c0[] = {78};
    ntru_append(&b0, (unsigned char*)&c0, 1);
    NtruBitStr b0_trail;
    ntru_trailing(&b0, 3, &b0_trail);
    unsigned char exp0[] = {6};
    int valid = equals_arr(b0_trail.buf, exp0, 1);

    NtruBitStr b1 = {{0}, 0, 0};
    unsigned char c1[] = {78, 251};
    ntru_append(&b1, (unsigned char*)&c1, 2);
    NtruBitStr b1_trail;
    ntru_trailing(&b1, 9, &b1_trail);
    unsigned char exp1[] = {78, 1};
    valid &= equals_arr(b1_trail.buf, exp1, 2);

    unsigned char c2[] = {100};
    ntru_append(&b1_trail, (unsigned char*)&c2, 1);
    unsigned char exp2[] = {78, 201};
    valid &= equals_arr((unsigned char*)&b1_trail.buf, (unsigned char*)&exp2, 2);
    NtruBitStr b2_trail;
    ntru_trailing(&b1_trail, 13, &b2_trail);
    unsigned char exp3[] = {78, 9};
    valid &= equals_arr(b2_trail.buf, exp3, 2);
    ntru_trailing(&b1_trail, 11, &b2_trail);
    unsigned char exp4[] = {78, 1};
    valid &= equals_arr(b2_trail.buf, exp4, 2);

    unsigned char c3[] = {100};
    ntru_append(&b2_trail, (unsigned char*)&c3, 1);
    unsigned char exp5[] = {78, 33, 3};
    valid &= equals_arr(b2_trail.buf, exp5, 3);
    ntru_trailing(&b2_trail, 16, &b1_trail);
    unsigned char exp6[] = {78, 33};
    valid &= equals_arr(b1_trail.buf, exp6, 2);

    print_result("test_trailing", valid);
    return valid;
}

int test_leading() {
    int valid = 1;

    NtruBitStr b0 = {{0}, 0, 0};
    unsigned char c0[] = {78, 42};
    ntru_append(&b0, (unsigned char*)&c0, 2);
    valid &= ntru_leading(&b0, 3) == 1;
    valid &= ntru_leading(&b0, 9) == 84;
    valid &= ntru_leading(&b0, 11) == 338;

    NtruBitStr b1;
    ntru_trailing(&b0, 11, &b1);
    unsigned char exp0[] = {78, 2};
    valid &= equals_arr(b1.buf, exp0, 2);
    valid &= ntru_leading(&b1, 11) == 590;
    valid &= ntru_leading(&b1, 5) == 9;

    unsigned char c1[] = {115};
    ntru_append(&b1, (unsigned char*)&c1, 1);
    valid &= ntru_leading(&b1, 9) == 230;
    valid &= ntru_leading(&b1, 11) == 922;

    unsigned char c2[] = {220};
    ntru_append(&b1, (unsigned char*)&c2, 1);
    valid &= ntru_leading(&b1, 6) == 55;

    print_result("test_leading", valid);
    return valid;
}

int test_bitstring() {
    int valid = test_append();
    valid &= test_trailing();
    valid &= test_leading();

    return valid;
}
