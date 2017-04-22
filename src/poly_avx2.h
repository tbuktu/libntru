#ifndef NTRU_POLY_AVX2_H
#define NTRU_POLY_AVX2_H

#include <stdint.h>
#include "types.h"

/*************************************
 * AVX2 versions of poly.c functions *
 *************************************/

/**
 * @brief Multiplication of two general polynomials with a modulus, AVX2 version
 *
 * Multiplies a NtruIntPoly by another, taking the coefficient values modulo an integer.
 * The number of coefficients must be the same for both polynomials.
 * Requires AVX2 support.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to multiply by
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply to the coefficients of c
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_int_avx2(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief General polynomial by ternary polynomial multiplication, AVX2 version
 *
 * Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients
 * must be the same for both polynomials.
 * This variant requires AVX2 support.
 *
 * @param a a general polynomial
 * @param b a ternary polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_tern_avx2(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask);

void ntru_mod_avx2(NtruIntPoly *p, uint16_t mod_mask);

void ntru_mod3_avx2(NtruIntPoly *p);

#endif   /* NTRU_POLY_AVX2_H */
