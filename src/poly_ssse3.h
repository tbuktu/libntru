#ifndef NTRU_POLY_SSSE3_H
#define NTRU_POLY_SSSE3_H

#include <stdint.h>
#include "types.h"

/**************************************
 * SSSE3 versions of poly.c functions *
 **************************************/

/**
 * @brief Multiplication of two general polynomials with a modulus, SSSE3 version
 *
 * Multiplies a NtruIntPoly by another, taking the coefficient values modulo an integer.
 * The number of coefficients must be the same for both polynomials.
 * Requires SSSE3 support.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to multiply by
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply to the coefficients of c
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_int_sse(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief General polynomial by ternary polynomial multiplication, SSSE3 version
 *
 * Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients
 * must be the same for both polynomials.
 * This variant requires SSSE3 support.
 *
 * @param a a general polynomial
 * @param b a ternary polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_tern_sse(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask);

void ntru_to_arr_sse(NtruIntPoly *p, uint16_t q, uint8_t *a);

/**
 * @brief Polynomial to binary
 *
 * Converts a NtruIntPoly to a uint8_t array. q is assumed to be 2048, so
 * each coefficient is encoded in 11 bits.
 * Requires SSSE3 support.
 *
 * @param p a polynomial
 * @param a output parameter; a pointer to store the encoded polynomial.
 *          Must accommodate at least 7 more bytes than the result takes up.
 */
void ntru_to_arr_sse_2048(NtruIntPoly *p, uint8_t *a);

void ntru_mod_sse(NtruIntPoly *p, uint16_t mod_mask);

void ntru_mod3_sse(NtruIntPoly *p);

#endif   /* NTRU_POLY_SSSE3_H */
