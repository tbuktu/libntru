#define NTRU_MAX_N 1499
#define NTRU_MAX_ONES 248

/** A polynomial with integer coefficients. */
typedef struct NtruIntPoly {
    int N;
    int coeffs[NTRU_MAX_N];
} NtruIntPoly;

/** A ternary polynomial, i.e. all coefficients are equal to -1, 0, or 1. */
typedef struct NtruTernPoly {
    int N;
    int num_ones;
    int num_neg_ones;
    int ones[NTRU_MAX_ONES];
    int neg_ones[NTRU_MAX_ONES];
} NtruTernPoly;

/**
 * A product-form polynomial, i.e. a polynomial of the form f1*f2+f3
 * where f1,f2,f3 are very sparsely populated ternary polynomials.
 */
typedef struct NtruProdPoly {
    int N;
    NtruTernPoly f1, f2, f3;
} NtruProdPoly;

/**
 * @brief Random product-form polynomial
 *
 * Generates a random product-form polynomial consisting of 3 random ternary polynomials.
 *
 * @param N the number of coefficients; must be NTRU_MAX_N or less
 * @param df1 number of ones and negative ones in the first ternary polynomial
 * @param df2 number of ones and negative ones in the second ternary polynomial
 * @param df3_ones number of ones ones in the third ternary polynomial
 * @param df3_neg_ones number of negative ones in the third ternary polynomial
 * @param poly output parameter; a pointer to store the new polynomial
 * @param rng a pointer to a function that takes an array and an array size, and fills the array
              with random data. See dev_random() and dev_urandom().
 */
void ntru_rand_prod(int N, int df1, int df2, int df3_ones, int df3_neg_ones, NtruProdPoly *poly, int (*rng)(unsigned[], int));

/**
 * @brief Ternary to general integer polynomial
 *
 * Converts a NtruTernPoly to an equivalent NtruIntPoly.
 *
 * @param a a ternary polynomial
 * @param b output parameter; a pointer to store the new polynomial
 */
void ntru_tern_to_int(NtruTernPoly *a, NtruIntPoly *b);

/**
 * @brief Product-form to general polynomial
 *
 * Converts a NtruProdPoly to an equivalent NtruIntPoly.
 *
 * @param a a product-form polynomial
 * @param b output parameter; a pointer to store the new polynomial
 */
void ntru_prod_to_int(NtruProdPoly *a, NtruIntPoly *b);

/**
 * @brief General polynomial by ternary polynomial multiplication
 *
 * Multiplies a NtruIntPoly by a NtruTernPoly. The number of coefficients
 * must be the same for both polynomials.
 *
 * @param a a general polynomial
 * @param b a ternary polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
int ntru_mult_tern(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c);

/**
 * @brief Multiplies a polynomial by a factor
 *
 * Multiplies each coefficient of an NtruIntPoly by an int.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param factor the factor to multiply by
 */
void ntru_mult_fac(NtruIntPoly *a, int factor);

/**
 * @brief Multiplication of two general polynomials
 *
 * Multiplies a NtruIntPoly by another. The number of coefficients
 * must be the same for both polynomials.
 *
 * @param a a general polynomial
 * @param b a general polynomial
 * @param c output parameter; a pointer to store the new polynomial
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
int ntru_mult_int(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c);

/**
 * @brief Multiplication of two general polynomials with a modulus
 *
 * Multiplies a NtruIntPoly by another, taking the coefficient values modulo an int.
 * The number of coefficients must be the same for both polynomials.
 *
 * @param a input and output parameter; coefficients are overwritten
 * @param b a polynomial to multiply by
 * @param c output parameter; a pointer to store the new polynomial
 * @param modulus the modulus to apply to the coefficients of c
 * @return 0 if the number of coefficients differ, 1 otherwise
 */
int ntru_mult_int_mod(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, int modulus);

/**
 * @brief Reduction modulo an int
 *
 * Reduces the coefficients of an NtruIntPoly modulo an int.
 *
 * @param p input and output parameter; coefficients are overwritten
 * @param modulus the modulus to apply to the coefficients of c
 */
void ntru_mod(NtruIntPoly *p, int modulus);

/**
 * @brief Equality with one
 *
 * Tests if p(x) = 1
 *
 * @param p a polynomial
 * @return 1 iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1
 */
int ntru_equals1(NtruIntPoly *p);

/**
 * @brief Inverse modulo q
 *
 * Computes the inverse mod q; q must be a power of 2.
 * Returns 0 if the polynomial is not invertible, 1 otherwise.
 * The algorithm is described in "Almost Inverses and Fast NTRU Key Generation" at
 * http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf
 *
 * @param a a polynomial
 * @param q the modulus
 * @param b output parameter; a pointer to store the new polynomial
 * @return 1 if a is invertible, 0 otherwise
 */
int ntru_invert(NtruIntPoly *a, int q, NtruIntPoly *b);

/**
 * @brief /dev/random-based RNG
 *
 * Fills an array with random data from /dev/random.
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @return 0 for error, 1 otherwise
 */
int dev_random(unsigned rand_data[], int len);

/**
 * @brief /dev/urandom-based RNG
 *
 * Fills an array with random data from /dev/urandom.
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @return 0 for error, 1 otherwise
 */
int dev_urandom(unsigned rand_data[], int len);
