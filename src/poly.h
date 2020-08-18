#ifndef NTRU_POLY_H
#define NTRU_POLY_H

#include <stdint.h>
#include "rand.h"
#include "types.h"

/**
 * @brief NTRU Prime multiplication
 *
 * Multiplies two NtruIntPolys modulo q. Both are assumed to be reduced mod q.
 *
 * @param a a polynomial
 * @param b a polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param modulus
 */
uint8_t ntruprime_mult_poly(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus);

/**
 * @brief Random small polynomial
 *
 * Generates a random ternary polynomial for NTRU Prime.
 *
 * @param N the number of coefficients; must be NTRU_MAX_DEGREE or less
 * @param poly output parameter; a pointer to store the new polynomial
 * @param rand_ctx a random number generator
 * @return 1 for success, 0 for failure
 */
uint8_t ntruprime_rand_tern(uint16_t N, NtruIntPoly *poly, NtruRandContext *rand_ctx);

/**
 * @brief Random t-small polynomial
 *
 * Generates a random ternary polynomial for NTRU Prime with t nonzero coefficients.
 *
 * @param N the number of coefficients; must be NTRU_MAX_DEGREE or less
 * @param t number of ones + number of negative ones
 * @param poly output parameter; a pointer to store the new polynomial
 * @param rand_ctx a random number generator
 * @return 1 for success, 0 for failure
 */
uint8_t ntruprime_rand_tern_t(uint16_t N, uint16_t t, NtruIntPoly *poly, NtruRandContext *rand_ctx);

/* Multiplies a polynomial by an integer, modulo another integer */
void ntruprime_mult_mod(NtruIntPoly *a, uint16_t factor, uint16_t modulus);

/**
 * @brief Modular inverse
 *
 * Computes the multiplicative inverse of a number using the extended Euclidean algorithm.
 *
 * @param a the input value
 * @param modulus
 * @return the inverse of a
 */
uint16_t ntruprime_inv_int(uint16_t a, uint16_t modulus);

/**
 * @brief Polynomial inverse
 *
 * Computes the multiplicative inverse of a polynomial in (Z/q)[x]/[x^p-x-1],
 * where p is given by a->N and q is given by modulus.
 *
 * @param a the input value
 * @param b output parameter; a pointer to store the inverse polynomial
 * @param modulus
 * @return 1 if a is invertible, 0 otherwise
 */
uint8_t ntruprime_inv_poly(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus);

/**
 * @brief Random ternary polynomial
 *
 * Generates a random ternary polynomial for NTRUEncrypt.
 *
 * @param N the number of coefficients; must be NTRU_MAX_DEGREE or less
 * @param num_ones number of ones
 * @param num_neg_ones number of negative ones
 * @param poly output parameter; a pointer to store the new polynomial
 * @param rand_ctx a random number generator
 * @return 1 for success, 0 for failure
 */
uint8_t ntru_rand_tern(uint16_t N, uint16_t num_ones, uint16_t num_neg_ones, NtruTernPoly *poly, NtruRandContext *rand_ctx);

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
/**
 * @brief Random product-form polynomial
 *
 * Generates a random product-form polynomial consisting of 3 random ternary polynomials.
 *
 * @param N the number of coefficients; must be NTRU_MAX_DEGREE or less
 * @param df1 number of ones and negative ones in the first ternary polynomial
 * @param df2 number of ones and negative ones in the second ternary polynomial
 * @param df3_ones number of ones ones in the third ternary polynomial
 * @param df3_neg_ones number of negative ones in the third ternary polynomial
 * @param poly output parameter; a pointer to store the new polynomial
 * @param rand_ctx a random number generator
 * @return 1 for success, 0 for failure
 */
uint8_t ntru_rand_prod(uint16_t N, uint16_t df1, uint16_t df2, uint16_t df3_ones, uint16_t df3_neg_ones, NtruProdPoly *poly, NtruRandContext *rand_ctx);
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

/**
 * @brief Addition of two polynomials
 *
 * Adds a NtruIntPoly to another.
 * The polynomial b must not have more coefficients than a.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to add to the polynomial a
 */
void ntru_add(NtruIntPoly *a, NtruIntPoly *b);

/**
 * @brief Subtraction of two polynomials
 *
 * Subtracts a NtruIntPoly from another.
 * The polynomial b must not have more coefficients than a.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to subtract from the polynomial a
 */
void ntru_sub(NtruIntPoly *a, NtruIntPoly *b);

/**
 * @brief General polynomial by ternary polynomial multiplication
 *
 * Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients
 * must be the same for both polynomials.
 *
 * @param a a general polynomial
 * @param b a ternary polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
extern uint8_t (*ntru_mult_tern)(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief General polynomial by ternary polynomial multiplication, 32 bit version
 *
 * Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients
 * must be the same for both polynomials.
 * Uses 32-bit arithmetic.
 *
 * @param a a general polynomial
 * @param b a ternary polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_tern_32(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief General polynomial by ternary polynomial multiplication, 64 bit version
 *
 * Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients
 * must be the same for both polynomials.
 * Uses 64-bit arithmetic.
 *
 * @param a a general polynomial
 * @param b a ternary polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_tern_64(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask);

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
/**
 * @brief General polynomial by product-form polynomial multiplication
 *
 * Multiplies a NtruIntPoly by a NtruProdPoly. The number of coefficients
 * must be the same for both polynomials.
 *
 * @param a a general polynomial
 * @param b a product-form polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_prod(NtruIntPoly *a, NtruProdPoly *b, NtruIntPoly *c, uint16_t mod_mask);
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

/**
 * @brief General polynomial by private polynomial multiplication
 *
 * Multiplies a NtruIntPoly by a NtruPrivPoly, i.e. a NtruTernPoly or
 * a NtruProdPoly. The number of coefficients must be the same for both
 * polynomials.
 *
 * @param a a "private" polynomial
 * @param b a general polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_priv(NtruPrivPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief Polynomial to binary
 *
 * Converts a NtruIntPoly to a uint8_t array. Each coefficient is encoded
 * in (log q) bits.
 * Uses 32-bit arithmetic.
 *
 * @param p a polynomial
 * @param q the modulus; must be a power of two
 * @param a output parameter; a pointer to store the encoded polynomial.
 *          No extra room is needed at the end.
 */
void ntru_to_arr_32(NtruIntPoly *p, uint16_t q, uint8_t *a);

/**
 * @brief Polynomial to binary
 *
 * Converts a NtruIntPoly to a uint8_t array. Each coefficient is encoded
 * in (log q) bits.
 * Uses 64-bit arithmetic.
 *
 * @param p a polynomial
 * @param q the modulus; must be a power of two
 * @param a output parameter; a pointer to store the encoded polynomial.
 *          Must accommodate at least 7 more bytes than the result takes up.
 */
void ntru_to_arr_64(NtruIntPoly *p, uint16_t q, uint8_t *a);

/**
 * @brief Polynomial to binary
 *
 * Converts a NtruIntPoly to a uint8_t array. Each coefficient is encoded
 * in (log q) bits.
 *
 * @param p a polynomial
 * @param q the modulus; must be a power of two
 * @param a output parameter; a pointer to store the encoded polynomial
 */
extern void (*ntru_to_arr)(NtruIntPoly *p, uint16_t q, uint8_t *a);

/**
 * @brief Polynomial to binary modulo 4
 *
 * Optimized version of ntru_to_arr() for q=4.
 * Encodes the low 2 bits of all coefficients in a uint8_t array.
 *
 * @param p a polynomial
 * @param arr output parameter; a pointer to store the encoded polynomial
 */
void ntru_to_arr4(NtruIntPoly *p, uint8_t *arr);

void ntru_from_arr(uint8_t *arr, uint16_t N, uint16_t q, NtruIntPoly *p);

/**
 * @brief Multiplies a polynomial by a factor
 *
 * Multiplies each coefficient of an NtruIntPoly by an integer.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param factor the factor to multiply by
 */
void ntru_mult_fac(NtruIntPoly *a, int16_t factor);

/**
 * @brief Multiplication of two general polynomials with a modulus
 *
 * Multiplies a NtruIntPoly by another, taking the coefficient values modulo an integer.
 * The number of coefficients must be the same for both polynomials.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to multiply by
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply to the coefficients of c
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
extern uint8_t (*ntru_mult_int)(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief Multiplication of two general polynomials with a modulus
 *
 * Multiplies a NtruIntPoly by another, taking the coefficient values modulo an integer.
 * The number of coefficients must be the same for both polynomials.
 * Uses 16-bit arithmetic.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to multiply by
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply to the coefficients of c
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_int_16(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief Multiplication of two general polynomials with a modulus, 64 bit version
 *
 * Multiplies a NtruIntPoly by another, taking the coefficient values modulo an integer.
 * The number of coefficients must be the same for both polynomials.
 * Uses 64-bit arithmetic.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to multiply by
 * @param c output parameter; a pointer to store the new polynomial
 * @param mod_mask an AND mask to apply to the coefficients of c
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
uint8_t ntru_mult_int_64(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask);

/**
 * @brief Reduction modulo a power of two
 *
 * Reduces the coefficients of an NtruIntPoly modulo a power of two.
 *
 * @param p input and output parameter; coefficients are overwritten
 * @param mod_mask an AND mask to apply to the coefficients of c
 */
extern void (*ntru_mod_mask)(NtruIntPoly *p, uint16_t mod_mask);

/**
 * @brief Reduction modulo 3
 *
 * Reduces the coefficients of an NtruIntPoly modulo 3 such that all
 * coefficients are ternary.
 *
 * @param p input and output parameter; coefficients are overwritten
 */
void ntru_mod3(NtruIntPoly *p);

/**
 * @brief Reduction modulo an integer, centered
 *
 * Reduces the coefficients of an NtruIntPoly modulo an integer such that
 * -q/2 <= p->coeffs[i] < q/2 for all coefficients.
 *
 * @param p input and output parameter; coefficients are overwritten
 * @param modulus the modulus to apply to the coefficients of p
 */
void ntru_mod_center(NtruIntPoly *p, uint16_t modulus);

/**
 * @brief Equality of two polynomials
 *
 * Tests if a(x) = b(x)
 *
 * @param a a polynomial
 * @param b a polynomial
 * @return 1 iff all coefficients are equal
 */
uint8_t ntru_equals_int(NtruIntPoly *a, NtruIntPoly *b);

/**
 * @brief Erases a private polynomial
 *
 * Overwrites all coefficients of a private (i.e., ternary or product-form)
 * polynomial with zeros.
 *
 * @param p a polynomial
 */
void ntru_clear_priv(NtruPrivPoly *p);

/**
 * @brief Erases a general polynomial
 *
 * Overwrites all coefficients of a polynomial with zeros.
 *
 * @param p a polynomial
 */
void ntru_clear_int(NtruIntPoly *p);

/**
 * @brief Inverse modulo q
 *
 * Computes the inverse of 1+3a mod q; q must be a power of 2.
 * Returns 0 if the polynomial is not invertible, 1 otherwise.
 * The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
 * http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
 *
 * @param a a ternary or product-form polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @param Fq output parameter; a pointer to store the new polynomial
 * @return 1 if a is invertible, 0 otherwise
 */
extern uint8_t (*ntru_invert)(NtruPrivPoly *a, uint16_t mod_mask, NtruIntPoly *Fq);

/**
 * @brief Inverse modulo q
 *
 * Computes the inverse of 1+3a mod q; q must be a power of 2.
 * Returns 0 if the polynomial is not invertible, 1 otherwise.
 * The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
 * http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
 * This function uses 32-bit arithmetic.
 *
 * @param a a ternary or product-form polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @param Fq output parameter; a pointer to store the new polynomial
 * @return 1 if a is invertible, 0 otherwise
 */
uint8_t ntru_invert_32(NtruPrivPoly *a, uint16_t mod_mask, NtruIntPoly *Fq);

/**
 * @brief Inverse modulo q
 *
 * Computes the inverse of 1+3a mod q; q must be a power of 2.
 * Returns 0 if the polynomial is not invertible, 1 otherwise.
 * The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
 * http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
 * This function uses 64-bit arithmetic.
 *
 * @param a a ternary or product-form polynomial
 * @param mod_mask an AND mask to apply; must be a power of two minus one
 * @param Fq output parameter; a pointer to store the new polynomial
 * @return 1 if a is invertible, 0 otherwise
 */
uint8_t ntru_invert_64(NtruPrivPoly *a, uint16_t mod_mask, NtruIntPoly *Fq);

/**
 * @brief Choose fastest implementation
 *
 * Sets function pointers for polynomial math, etc. so the most efficient
 * variant is used.
 */
void ntru_set_optimized_impl_poly();

#endif   /* NTRU_POLY_H */
