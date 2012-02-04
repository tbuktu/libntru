#include "poly.h"
#include "test_util.h"

int test_mult() {
    int valid = 1;

    /* multiplication modulo q */
    NtruIntPoly a1 = {11, {-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1}};
    NtruIntPoly b1 = {11, {14, 11, 26, 24, 14, 16, 30, 7, 25, 6, 19}};
    NtruIntPoly c1;
    ntru_mult_int_mod(&a1, &b1, &c1, 32);
    NtruIntPoly c1_exp = {11, {3, 25, -10, 21, 10, 7, 6, 7, 5, 29, -7}};
    valid &= equals_int(&c1_exp, &c1);

    /* multiplication without a modulus */
    NtruIntPoly a2 = {11, {1, 1, 0, 0, -1, -1, 0, 0, -1, 0, 1}};
    NtruIntPoly b2 = {11, {2, 14, -10, 10, -4, -10, 2, 12, 11, -2, 8}};
    NtruIntPoly c2;
    ntru_mult_int(&a2, &b2, &c2);
    NtruIntPoly c2_exp = {11, {0, -13, 15, -12, -26, -39, 2, 17, 13, 17, 26}};
    valid &= equals_int(&c2_exp, &c2);

    /* mult_mod should give the same result as mult followed by mod */
    NtruIntPoly a3 = {11, {1, 0, -1, 1, 0, 1, 1, 1, -1, 1, -1}};
    NtruIntPoly b3 = {11, {0, 1, 1, 0, 0, -1, -1, 1, 1, -1, 1}};
    NtruIntPoly c3, c3_exp;
    ntru_mult_int_mod(&a3, &b3, &c3, 20);
    ntru_mult_int(&a3, &b3, &c3_exp);
    ntru_mod(&c3_exp, 20);
    valid &= equals_int_mod(&c3_exp, &c3, 20);

    print_result("test_mult", valid);
    return valid;
}

int verify_inverse(NtruIntPoly *a, NtruIntPoly *b, int modulus) {
    NtruIntPoly c;
    ntru_mult_int_mod(a, b, &c, modulus);
    ntru_mod(&c, modulus);
    return ntru_equals1(&c);
}

int test_inv() {
    int valid = 1;

    /* Verify an example from the NTRU tutorial */
    NtruIntPoly a1 = {11, {-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1}};
    NtruIntPoly b1;
    int invertible = ntru_invert(&a1, 32, &b1);
    NtruIntPoly b_exp = {11, {5, -23, 6, 16, 4, 15, 16, -10, -12, -14, -2}};
    valid &= invertible;
    valid &= equals_int(&b_exp, &b1);
    valid &= verify_inverse(&a1, &b1, 32);

    /* Verify an example from the NTRU tutorial */
    int num_invertible = 0;
    while (num_invertible < 3) {
        NtruProdPoly a_prod;
        ntru_rand_prod(853, 8, 8, 8, 9, &a_prod, dev_urandom);
        NtruIntPoly a_int;
        ntru_prod_to_int(&a_prod, &a_int);
        ntru_mod(&a_int, 2048);

        NtruIntPoly b;
        int invertible = ntru_invert(&a_int, 2048, &b);
        if (invertible) {
            valid &= verify_inverse(&a_int, &b, 2048);
            num_invertible++;
        }
    }

    /* test a non-invertible polynomial */
    NtruIntPoly a2 = {11, {-1, 0, 1, 1, 0, 0, -1, 0, -1, 0, 1}};
    NtruIntPoly b2;
    invertible = ntru_invert(&a2, 32, &b2);
    valid &= !invertible;

    print_result("test_inv", valid);
    return valid;
}

int test_poly() {
    int valid = 1;
    valid &= test_mult();
    valid &= test_inv();
    return valid;
}
